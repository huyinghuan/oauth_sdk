package oauth_sdk

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"math"
	"net/http"
	"time"
)

type Scope struct {
	Name    string   `json:"name"`
	Type    string   `json:"type"`
	Actions []string `json:"actions"`
}

type VerityResult struct {
	StatusCode int
	Scope      Scope
}

type AuthScope struct {
	Timestamp int64 `json:"timestamp"`
	Scope     Scope `json:"scope"`
}

type ResourceOfAcccount struct {
	Timestamp int64  `json:"timestamp"`
	Username  string `json:"username"`
}

func verityTimestamp(timestamp int64) bool {
	return math.Abs(float64(timestamp-time.Now().Unix())) < 5*60
}

type SDK struct {
	Server     string
	PrivateKey string
	ClientID   string
}

func (sdk *SDK) RequestResource(token string, username string) (string, error) {
	data := map[string]interface{}{
		"timestamp": time.Now().Unix(),
		"token":     token,
	}
	dataBody, _ := json.Marshal(data)
	encryptData, err := CFBEncrypt(sdk.PrivateKey, string(dataBody))
	if err != nil {
		return "", err
	}
	req, err := http.NewRequest("POST", sdk.Server+"/resource/account", bytes.NewBuffer([]byte(encryptData)))
	if err != nil {
		return "", err
	}
	req.Header.Set("client-id", sdk.ClientID)
	req.Header.Set("account", username)
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("Get Statsu code: %d", resp.StatusCode)
	}

	encryptResponseBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	decryptResponseBody, err := CFBDecrypt(sdk.PrivateKey, string(encryptResponseBody))
	if err != nil {
		return "", err
	}
	account := ResourceOfAcccount{}
	json.Unmarshal([]byte(decryptResponseBody), &account)
	if !verityTimestamp(account.Timestamp) {
		return "", fmt.Errorf("数据时间戳校验失败")
	}
	return account.Username, nil
}

func (sdk *SDK) Verify(path string, method string, username string) (*VerityResult, error) {
	scope := Scope{
		Name: path,
		Type: method,
	}

	body, _ := json.Marshal(&scope)
	encryptBody, err := CFBEncryptBytes(sdk.PrivateKey, body)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequest("POST", sdk.Server+"/authorize", bytes.NewBuffer([]byte(encryptBody)))
	req.Header.Set("client-id", sdk.ClientID)
	req.Header.Set("account", username)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != 200 {
		return &VerityResult{
			StatusCode: resp.StatusCode,
		}, nil
	}

	encryptResponseBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	decryptResponseBody, err := CFBDecrypt(sdk.PrivateKey, string(encryptResponseBody))
	if err != nil {
		return nil, err
	}
	authScope := AuthScope{}
	if err := json.Unmarshal([]byte(decryptResponseBody), &authScope); err != nil {
		return nil, err
	}
	if !verityTimestamp(authScope.Timestamp) {
		return nil, fmt.Errorf("校验时间戳失败")
	}
	return &VerityResult{
		StatusCode: resp.StatusCode,
		Scope:      authScope.Scope,
	}, nil
}

func (sdk *SDK) GetAuthorizedURL() string {
	return fmt.Sprintf("%s?client_id=%s&t=%d", sdk.Server+"/authorize", sdk.ClientID, time.Now().Unix())
}
