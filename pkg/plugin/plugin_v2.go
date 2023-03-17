package plugin

import (
	"bytes"
	"context"
	cryptoRand "crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"math/rand"

	"crypto/aes"
	"crypto/cipher"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/kms"
	"github.com/aws/aws-sdk-go/service/kms/kmsiface"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	pbv2 "k8s.io/kms/apis/v2alpha1"
)

var _ pbv2.KeyManagementServiceServer = &PluginV2{}

type PluginV2 struct {
	encryptionCtx map[string]*string
	svc           kmsiface.KMSAPI
	keyID         string
	localKEKCache []localKEK
	currentKEK    localKEK
}

type localKEK struct {
	kek    string
	encKEK []byte
}

// New returns a new *Plugin
func NewV2(key string, svc kmsiface.KMSAPI, encryptionCtx map[string]string) *PluginV2 {
	bytes := make([]byte, 16) //generate a random 32 byte key for AES-256
	if _, err := rand.Read(bytes); err != nil {
		panic(err.Error())
	}
	kek := hex.EncodeToString(bytes) //encode key in bytes to string for saving

	p := &PluginV2{
		svc:   svc,
		keyID: key,
	}
	if len(encryptionCtx) > 0 {
		p.encryptionCtx = make(map[string]*string)
	}
	for k, v := range encryptionCtx {
		p.encryptionCtx[k] = aws.String(v)
	}
	input := &kms.EncryptInput{
		Plaintext:         []byte(kek),
		KeyId:             aws.String(key),
		EncryptionContext: p.encryptionCtx,
	}

	result, err := svc.Encrypt(input)
	if err != nil {
		panic(err)
	}
	p.localKEKCache = append(p.localKEKCache, localKEK{kek: kek, encKEK: result.CiphertextBlob})
	p.currentKEK = localKEK{kek: kek, encKEK: result.CiphertextBlob}
	zap.L().Info(fmt.Sprintf("Init: %v", p.currentKEK))

	return p
}

func (p *PluginV2) Decrypt(ctx context.Context, request *pbv2.DecryptRequest) (*pbv2.DecryptResponse, error) {
	zap.L().Info("starting decrypt operation")

	if string(request.Ciphertext[0]) == "1" {
		request.Ciphertext = request.Ciphertext[1:]
	}
	if kekEnc, ok := request.Annotations["kek-anno"]; ok {
		zap.L().Info(fmt.Sprintf("encrypted annotation %v", kekEnc))
		for _, k := range p.localKEKCache {
			if bytes.Equal(kekEnc, k.encKEK) {
				zap.L().Info(fmt.Sprintf("matched encrypted annotation %v", k.encKEK))

				b, err := aes.NewCipher([]byte(k.kek))
				if err != nil {
					zap.L().Info("err1:" + err.Error())
				}
				aesGCM, err := cipher.NewGCM(b)
				if err != nil {
					panic(err.Error())
				}
				//Get the nonce size
				nonceSize := aesGCM.NonceSize()

				//Extract the nonce from the encrypted data
				nonce, ciphertext := request.Ciphertext[:nonceSize], request.Ciphertext[nonceSize:]

				//Decrypt the data
				plaintext, err := aesGCM.Open(nil, nonce, ciphertext, nil)
				if err != nil {
					panic(err.Error())
				}

				return &pbv2.DecryptResponse{Plaintext: plaintext}, nil
			}
		}
		zap.L().Info(fmt.Sprintf("did not match. Decrypt kek %v", kekEnc))
		input := &kms.DecryptInput{
			CiphertextBlob: kekEnc,
		}
		if len(p.encryptionCtx) > 0 {
			zap.L().Info("configuring encryption context", zap.String("ctx", fmt.Sprintf("%v", p.encryptionCtx)))
			input.EncryptionContext = p.encryptionCtx
		}

		key, err := p.svc.Decrypt(input)
		if err != nil {
			zap.L().Error("request to decrypt failed", zap.String("error-type", err.Error()), zap.Error(err))
			return nil, fmt.Errorf("failed to decrypt %w", err)
		}
		p.localKEKCache = append(p.localKEKCache, localKEK{kek: string(key.Plaintext), encKEK: kekEnc})

		b, err := aes.NewCipher([]byte(key.Plaintext))
		if err != nil {
			zap.L().Info("err2:" + err.Error())
		}
		aesGCM, err := cipher.NewGCM(b)
		if err != nil {
			panic(err.Error())
		}
		//Get the nonce size
		nonceSize := aesGCM.NonceSize()

		//Extract the nonce from the encrypted data
		nonce, ciphertext := request.Ciphertext[:nonceSize], request.Ciphertext[nonceSize:]

		//Decrypt the data
		plaintext, err := aesGCM.Open(nil, nonce, ciphertext, nil)
		if err != nil {
			panic(err.Error())
		}
		return &pbv2.DecryptResponse{Plaintext: plaintext}, nil
	}
	panic("why no annotation")
}

func (p *PluginV2) Encrypt(ctx context.Context, request *pbv2.EncryptRequest) (*pbv2.EncryptResponse, error) {
	zap.L().Info(fmt.Sprintf("starting encrypt operation %v", p.currentKEK))
	b, err := aes.NewCipher([]byte(p.currentKEK.kek))
	if err != nil {
		zap.L().Info("err2:" + err.Error())
	}

	aesGCM, err := cipher.NewGCM(b)
	if err != nil {
		panic(err.Error())
	}
	nonce := make([]byte, aesGCM.NonceSize())
	if _, err = io.ReadFull(cryptoRand.Reader, nonce); err != nil {
		panic(err.Error())
	}
	ciphertext := aesGCM.Seal(nonce, nonce, request.Plaintext, nil)

	zap.L().Info("encrypt operation successful")
	return &pbv2.EncryptResponse{Ciphertext: append([]byte("1"), ciphertext...), KeyId: p.keyID, Annotations: map[string][]byte{"kek-anno": []byte(p.currentKEK.encKEK)}}, nil
}

func (p *PluginV2) Status(context.Context, *pbv2.StatusRequest) (*pbv2.StatusResponse, error) {
	return &pbv2.StatusResponse{
		Version: "v2alpha1",
		Healthz: "ok",
		KeyId:   p.keyID,
	}, nil
}

func (p *PluginV2) Register(s *grpc.Server) {
	zap.L().Info("registering the kms plugin with grpc server")
	pbv2.RegisterKeyManagementServiceServer(s, p)
}
