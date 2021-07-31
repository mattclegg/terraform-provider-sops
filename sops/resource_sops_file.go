package sops

import (
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"github.com/hashicorp/terraform-plugin-sdk/helper/schema"
	sops "go.mozilla.org/sops/v3"
	age "go.mozilla.org/sops/v3/age"
	sopsKms "go.mozilla.org/sops/v3/kms"
	"io/ioutil"
	"os"
	"path"
	"strconv"
)

func resourceSourceFile() *schema.Resource {
	return &schema.Resource{
		Schema: map[string]*schema.Schema{
			"filename": {
				Type:     schema.TypeString,
				Optional: false,
				ForceNew: true,
			},
			"encryption_type": {
				Type:     schema.TypeString,
				Optional: false,
				ForceNew: true,
			},
			"content": {
				Type:     schema.TypeString,
				Optional: true,
				ForceNew: true,
			},
			"kms": {
				Type:     schema.TypeMap,
				Optional: true,
				ForceNew: true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			"age": {
				Type:     schema.TypeMap,
				Optional: true,
				ForceNew: true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
		},
		Create: resourceSopsFileCreate,
		Update: func(data *schema.ResourceData, i interface{}) error {
			return nil
		},
		Delete: resourceSopsFileDelete,
	}

}

func resourceSopsFileDelete(d *schema.ResourceData, _ interface{}) error {
	os.Remove(d.Get("filename").(string))
	return nil
}

func resourceLocalFileContent(d *schema.ResourceData) ([]byte, error) {
	if content, sensitiveSpecified := d.GetOk("sensitive_content"); sensitiveSpecified {
		return []byte(content.(string)), nil
	}
	if b64Content, b64Specified := d.GetOk("content_base64"); b64Specified {
		return base64.StdEncoding.DecodeString(b64Content.(string))
	}

	if v, ok := d.GetOk("source"); ok {
		source := v.(string)
		return ioutil.ReadFile(source)
	}

	content := d.Get("content")
	return []byte(content.(string)), nil
}

func sopsEncrypt(d *schema.ResourceData, content *string) ([]byte, error) {
	encType := d.Get("encryption_type").(string)
	encryptionKey, err := getEncryptionKey(d, encType)
	if err != nil {
		return nil, err
	}
	encrypt, err := sops.Cipher.Encrypt(nil, content, encryptionKey, "")
	if err != nil {
		return nil, err
	}
	return []byte(encrypt), nil
}

func getEncryptionKey(d *schema.ResourceData, encType string) ([]byte, error) {
	var encryptionKey []byte
	switch encType {
	case "kms":
		kmsConf := d.Get("kms").(schema.ResourceData)
		arn := kmsConf.Get("arn")
		if arn == nil {
			return nil, fmt.Errorf("arn is not set")
		}
		profile := kmsConf.Get("profile")
		if profile == nil {
			return nil, fmt.Errorf("AWS profile is not set")
		}
		masterKey := sopsKms.NewMasterKeyFromArn(arn.(string), nil, profile.(string))
		encryptionKey = masterKey.EncryptedDataKey()
	case "age":
		ageConf := d.Get("age").(schema.ResourceData)
		ageKey := ageConf.Get("key")
		if ageKey == nil {
			return nil, fmt.Errorf("Age key is not set")
		}
		key, err := age.MasterKeyFromRecipient(ageKey.(string))
		if err != nil {
			return nil, err
		}
		encryptionKey = key.EncryptedDataKey()
	}
	return encryptionKey, nil
}

func resourceSopsFileCreate(d *schema.ResourceData, i interface{}) error {

	content, err := resourceLocalFileContent(d)
	if err != nil {
		return err
	}
	strContent := string(content)
	content, err = sopsEncrypt(d, &strContent)
	if err != nil {
		return err
	}
	//content = encrypt
	destination := d.Get("filename").(string)

	destinationDir := path.Dir(destination)
	if _, err := os.Stat(destinationDir); err != nil {
		dirPerm := d.Get("directory_permission").(string)
		dirMode, _ := strconv.ParseInt(dirPerm, 8, 64)
		if err := os.MkdirAll(destinationDir, os.FileMode(dirMode)); err != nil {
			return err
		}
	}

	filePerm := d.Get("file_permission").(string)
	fileMode, _ := strconv.ParseInt(filePerm, 8, 64)

	if err := ioutil.WriteFile(destination, content, os.FileMode(fileMode)); err != nil {
		return err
	}

	checksum := sha1.Sum(content)
	d.SetId(hex.EncodeToString(checksum[:]))

	return nil

}
