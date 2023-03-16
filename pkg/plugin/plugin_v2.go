package plugin

import (
	"context"
	"fmt"

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
}

// New returns a new *Plugin
func NewV2(key string, svc kmsiface.KMSAPI, encryptionCtx map[string]string) *PluginV2 {
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
	return p
}

func (p *PluginV2) Decrypt(ctx context.Context, request *pbv2.DecryptRequest) (*pbv2.DecryptResponse, error) {
	zap.L().Info("starting decrypt operation")

	if string(request.Ciphertext[0]) == "1" {
		request.Ciphertext = request.Ciphertext[1:]
	}
	input := &kms.DecryptInput{
		CiphertextBlob: request.Ciphertext,
		KeyId:          aws.String(p.keyID),
	}
	if len(p.encryptionCtx) > 0 {
		zap.L().Info("configuring encryption context", zap.String("ctx", fmt.Sprintf("%v", p.encryptionCtx)))
		input.EncryptionContext = p.encryptionCtx
	}

	result, err := p.svc.Decrypt(input)
	if err != nil {
		zap.L().Error("request to decrypt failed", zap.String("error-type", err.Error()), zap.Error(err))
		return nil, fmt.Errorf("failed to decrypt %w", err)
	}

	zap.L().Info("decrypt operation successful")
	return &pbv2.DecryptResponse{Plaintext: result.Plaintext}, nil
}

func (p *PluginV2) Encrypt(ctx context.Context, request *pbv2.EncryptRequest) (*pbv2.EncryptResponse, error) {
	zap.L().Info("starting encrypt operation")

	input := &kms.EncryptInput{
		Plaintext: request.Plaintext,
		KeyId:     aws.String(p.keyID),
	}
	if len(p.encryptionCtx) > 0 {
		zap.L().Info("configuring encryption context", zap.String("ctx", fmt.Sprintf("%v", p.encryptionCtx)))
		input.EncryptionContext = p.encryptionCtx
	}

	result, err := p.svc.Encrypt(input)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt %w", err)
	}

	zap.L().Info("encrypt operation successful")
	return &pbv2.EncryptResponse{Ciphertext: append([]byte("1"), result.CiphertextBlob...)}, nil
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
