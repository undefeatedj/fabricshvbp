package spacehardecdsa

import (
	"crypto/ecdsa"
	"testing"
)

var priv *ecdsa.PrivateKey
var message = "today is a good day"

//func TestGenerateTable(test *testing.T){
//	priv,_ = keygen()
//	generateTable(128,40,priv)
//}
//
//func TestWBObfSignAndVerify(t *testing.T) {
//
//	priv,_ = keygen()
//	generateTable(128,40,priv)
//	r,s:=WBObfECDSASign([]byte(message),128)
//
//	if !ecdsa.Verify(priv.Public().(*ecdsa.PublicKey),Keccak256([]byte(message)),r,s) {
//		fmt.Errorf("can not verify")
//	}
//}
//
//
//func BenchmarkKeyGen(b *testing.B)  {
//	b.ResetTimer()
//	for i:=0;i<b.N;i++{
//		keygen()
//	}
//}

func BenchmarkWBObfGenerateTableN_T(b *testing.B)  {
	//fmt.Println("hello!")
	priv, _= keygen()
	b.ResetTimer()
	for i:=0;i<b.N;i++{
		generateTable(61,30,priv)
	}
}

func BenchmarkWBObfSign(b *testing.B) {

	b.ResetTimer()
	for i:=0;i<b.N;i++{
		WBObfECDSASign([]byte(message),61)
	}
}


