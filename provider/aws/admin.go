package aws

import (
	"context"
	"io/ioutil"
	"encoding/base64"
	"encoding/json"

	log "github.com/sirupsen/logrus"

	"github.com/pkg/errors"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/awserr"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
)

func (c Client) uploadAdminKeys() error {
	filename := "/etc/kubernetes/admin.conf"
	content, err := ioutil.ReadFile(filename)
	if err != nil {
		return errors.WithMessagef(err, "error reading file %s", filename)
	}

	svc := secretsmanager.New(c.Cfg)
	input := &secretsmanager.PutSecretValueInput{
		SecretId:           aws.String(c.ClusterName()+"-admin"),
		SecretString:       aws.String("{\"ADMIN_CONF\":\""+base64.RawURLEncoding.EncodeToString(content)+"\"}"),
	}

	req := svc.PutSecretValueRequest(input)
	_, err = req.Send(context.Background())
	if err != nil {
		if aerr, ok := err.(awserr.Error); ok {
			switch aerr.Code() {
			case secretsmanager.ErrCodeInvalidParameterException:
				log.Error(secretsmanager.ErrCodeInvalidParameterException, aerr.Error())
			case secretsmanager.ErrCodeInvalidRequestException:
				log.Error(secretsmanager.ErrCodeInvalidRequestException, aerr.Error())
			case secretsmanager.ErrCodeLimitExceededException:
				log.Error(secretsmanager.ErrCodeLimitExceededException, aerr.Error())
			case secretsmanager.ErrCodeEncryptionFailure:
				log.Error(secretsmanager.ErrCodeEncryptionFailure, aerr.Error())
			case secretsmanager.ErrCodeResourceExistsException:
				log.Error(secretsmanager.ErrCodeResourceExistsException, aerr.Error())
			case secretsmanager.ErrCodeResourceNotFoundException:
				log.Error(secretsmanager.ErrCodeResourceNotFoundException, aerr.Error())
			case secretsmanager.ErrCodeInternalServiceError:
				log.Error(secretsmanager.ErrCodeInternalServiceError, aerr.Error())
			default:
				log.Error(aerr.Error())
			}
		} else {
			// Print the error, cast err to awserr.Error to get the Code and
			// Message from an error.
			log.Error(err.Error())
		}
		return err
	}
	return nil
}

type admin struct {
	Key string `json:"ADMIN_CONF"`
}

func (c Client) FetchAdminKeys() (string, error) {
	svc := secretsmanager.New(c.Cfg)
	input := &secretsmanager.GetSecretValueInput{
		SecretId:     aws.String(c.Id+"-admin"),
		VersionStage: aws.String("AWSCURRENT"),
	}

	req := svc.GetSecretValueRequest(input)
	result, err := req.Send(context.Background())
	if err != nil {
		if aerr, ok := err.(awserr.Error); ok {
			switch aerr.Code() {
			case secretsmanager.ErrCodeResourceNotFoundException:
				log.Error(secretsmanager.ErrCodeResourceNotFoundException, aerr.Error())
			case secretsmanager.ErrCodeInvalidParameterException:
				log.Error(secretsmanager.ErrCodeInvalidParameterException, aerr.Error())
			case secretsmanager.ErrCodeInvalidRequestException:
				log.Error(secretsmanager.ErrCodeInvalidRequestException, aerr.Error())
			case secretsmanager.ErrCodeDecryptionFailure:
				log.Error(secretsmanager.ErrCodeDecryptionFailure, aerr.Error())
			case secretsmanager.ErrCodeInternalServiceError:
				log.Error(secretsmanager.ErrCodeInternalServiceError, aerr.Error())
			default:
				log.Error(aerr.Error())
			}
		} else {
			log.Error(err.Error())
		}
		return "", err
	}

	var adm admin
	err = json.Unmarshal([]byte(*result.SecretString), &adm)
	if err != nil {
		log.Errorf("failed to unmarshall secretString [%s] %v", c.Id+"-admin", err)
		return "", err
	}
	secret, err := base64.RawURLEncoding.DecodeString(adm.Key)
	if err != nil {
		log.Errorf("failed to decode b64 secretString [%s] %v", c.Id+"-admin", err)
		return "", err
	}

	return string(secret), nil
}
