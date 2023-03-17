/*
Copyright 2020 The Kubernetes Authors.
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at
    http://www.apache.org/licenses/LICENSE-2.0
Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package plugin

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	cryptoRand "crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	//nolint

	"github.com/aws/aws-sdk-go/service/kms"
	"github.com/aws/aws-sdk-go/service/kms/kmsiface"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	pb "k8s.io/kms/apis/v1beta1"
	"sigs.k8s.io/aws-encryption-provider/pkg/version"
)

// StorageVersion is a prefix used for versioning encrypted content
const StorageVersionV2 = "2"

var _ pb.KeyManagementServiceServer = &PluginV3{}

// Plugin implements the KeyManagementServiceServer
type PluginV3 struct {
	svc           kmsiface.KMSAPI
	keyID         string
	encryptionCtx map[string]*string
	kek           string
	encKEK        []byte
}

// New returns a new *Plugin
func NewV3(key string, svc kmsiface.KMSAPI, encryptionCtx map[string]string, kekEnc string) *PluginV3 {
	return newPluginV3(
		key,
		svc,
		encryptionCtx,
		kekEnc,
	)
}

func newPluginV3(
	key string,
	svc kmsiface.KMSAPI,
	encryptionCtx map[string]string,
	kekEnc string,
) *PluginV3 {
	enc, _ := base64.StdEncoding.DecodeString(kekEnc)
	p := &PluginV3{
		svc:    svc,
		keyID:  key,
		encKEK: enc,
	}
	if len(encryptionCtx) > 0 {
		p.encryptionCtx = make(map[string]*string)
	}
	for k, v := range encryptionCtx {
		p.encryptionCtx[k] = aws.String(v)
	}
	input := &kms.DecryptInput{
		CiphertextBlob:    p.encKEK,
		EncryptionContext: p.encryptionCtx,
	}
	result, err := svc.Decrypt(input)
	if err != nil {
		panic(err)
	}
	p.kek = string(result.Plaintext)
	fmt.Println("***")
	fmt.Println(p.kek)
	fmt.Println("***")
	return p
}

// Version returns the plugin server version
func (p *PluginV3) Version(ctx context.Context, request *pb.VersionRequest) (*pb.VersionResponse, error) {
	return &pb.VersionResponse{
		Version:        version.APIVersion,
		RuntimeName:    version.Runtime,
		RuntimeVersion: version.Version,
	}, nil
}

// Encrypt executes the encryption operation using AWS KMS
func (p *PluginV3) Encrypt(ctx context.Context, request *pb.EncryptRequest) (*pb.EncryptResponse, error) {
	zap.L().Debug("starting encrypt operation")
	startTime := time.Now()
	b, err := aes.NewCipher([]byte(p.kek))
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
	ciphertext := aesGCM.Seal(nonce, nonce, request.Plain, nil)

	zap.L().Debug("encrypt operation successful")
	kmsLatencyMetric.WithLabelValues(p.keyID, statusSuccess, operationEncrypt).Observe(getMillisecondsSince(startTime))
	kmsOperationCounter.WithLabelValues(p.keyID, statusSuccess, operationEncrypt).Inc()
	return &pb.EncryptResponse{Cipher: append([]byte(StorageVersionV2), ciphertext...)}, nil
}

// Decrypt executes the decrypt operation using AWS KMS
func (p *PluginV3) Decrypt(ctx context.Context, request *pb.DecryptRequest) (*pb.DecryptResponse, error) {
	zap.L().Debug("starting decrypt operation")

	if string(request.Cipher[0]) == StorageVersion {
		return p.decryptV1(ctx, request)
	}
	return p.decryptV2(ctx, request)
}

func (p *PluginV3) decryptV2(ctx context.Context, request *pb.DecryptRequest) (*pb.DecryptResponse, error) {
	zap.L().Info("starting decrypt operation")

	if string(request.Cipher[0]) == "2" {
		request.Cipher = request.Cipher[1:]
	}
	b, err := aes.NewCipher([]byte(p.kek))
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
	nonce, ciphertext := request.Cipher[:nonceSize], request.Cipher[nonceSize:]

	//Decrypt the data
	plaintext, err := aesGCM.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		panic(err.Error())
	}
	return &pb.DecryptResponse{Plain: plaintext}, nil
}

func (p *PluginV3) decryptV1(ctx context.Context, request *pb.DecryptRequest) (*pb.DecryptResponse, error) {
	zap.L().Debug("starting decrypt operation")

	startTime := time.Now()
	if string(request.Cipher[0]) == StorageVersion {
		request.Cipher = request.Cipher[1:]
	}
	input := &kms.DecryptInput{
		CiphertextBlob: request.Cipher,
	}
	if len(p.encryptionCtx) > 0 {
		zap.L().Debug("configuring encryption context", zap.String("ctx", fmt.Sprintf("%v", p.encryptionCtx)))
		input.EncryptionContext = p.encryptionCtx
	}

	result, err := p.svc.Decrypt(input)
	if err != nil {
		zap.L().Error("request to decrypt failed", zap.String("error-type", ParseError(err).String()), zap.Error(err))
		failLabel := getStatusLabel(err)
		kmsLatencyMetric.WithLabelValues(p.keyID, failLabel, operationDecrypt).Observe(getMillisecondsSince(startTime))
		kmsOperationCounter.WithLabelValues(p.keyID, failLabel, operationDecrypt).Inc()
		return nil, fmt.Errorf("failed to decrypt %w", err)
	}

	zap.L().Debug("decrypt operation successful")
	kmsLatencyMetric.WithLabelValues(p.keyID, statusSuccess, operationDecrypt).Observe(getMillisecondsSince(startTime))
	kmsOperationCounter.WithLabelValues(p.keyID, statusSuccess, operationDecrypt).Inc()
	return &pb.DecryptResponse{Plain: result.Plaintext}, nil
}

// Register registers the plugin with the grpc server
func (p *PluginV3) Register(s *grpc.Server) {
	zap.L().Info("registering the kms plugin with grpc server")
	pb.RegisterKeyManagementServiceServer(s, p)
}

// NewClient returns a KeyManagementServiceClient for a given grpc connection
func NewClientV3(conn *grpc.ClientConn) pb.KeyManagementServiceClient {
	return pb.NewKeyManagementServiceClient(conn)
}
