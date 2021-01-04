package sw

import (
	"bufio"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"golang.org/x/crypto/sha3"
	"io"
	"log"
	"math/big"
	"os"
	"strconv"
	"strings"
)
//签名所需要的工具类

//定义多项式结构体
type Polynomial struct {
	coefficients []*big.Int //系数数组
	a0 *big.Int;//多项式0点
}

//生成任意0点值的degree阶多项式
func generatePolynomial(degree int)(poly Polynomial) {
	var poly1 Polynomial;
	x,_:=GenerateRandomNumber()
	//fmt.Println(x)
	poly1.a0=x
	var coefs []*big.Int
	for i:=0;i<degree;i++{
		coef,_:=GenerateRandomNumber()//rand.Int(rand.Reader,big.NewInt(1024))
		//fmt.Println(coef)
		coefs=append(coefs,coef)
	}
	poly1.coefficients=coefs
	return poly1
}

//生成degree阶多项式，且可传入0点值
func generateUniquePolynomial(degree  int,a0 *big.Int)(poly Polynomial) {
	var poly1 Polynomial

	poly1.a0 = a0//设置多项式的0点
	var coefs []*big.Int
	for i:=0;i<degree;i++{
		coef,_:=GenerateRandomNumber()//rand.Int(rand.Reader,big.NewInt(1024))
		//fmt.Println(coef)
		coefs=append(coefs,coef)
	}
	poly1.coefficients=coefs
	return poly1
}

//产生关于aG的多项式
func generateGPolynomial(degree int,x *big.Int)(polyx Polynomial,polyy Polynomial) {
	var poly1 Polynomial;var poly2 Polynomial;
	fmt.Println(x)
	ax,ay:= elliptic.P256().ScalarBaseMult(x.Bytes())//S256().ScalarBaseMult(x.Bytes())//计算aG
	fmt.Println(ax)
	fmt.Println(ay)
	//产生0点是ax的多项式
	poly1.a0=ax
	var coefs []*big.Int
	for i:=0;i<degree;i++{
		coef,_:=GenerateRandomNumber()//rand.Int(rand.Reader,big.NewInt(1024))
		//fmt.Println(coef)
		coefs=append(coefs,coef)
	}
	poly1.coefficients=coefs
	//产生0点是y的多项式
	poly2.a0=ay
	var coefs2 []*big.Int
	for i:=0;i<degree;i++{
		coef2,_:=rand.Int(rand.Reader,big.NewInt(1024))
		//fmt.Println(coef)
		coefs2=append(coefs2,coef2)
	}
	return poly1,poly2
}

//生成0点是0的多项式
func generateZeroPolynomial(degree int)(poly Polynomial) {
	var poly1 Polynomial;
	x:=big.NewInt(0)
	//fmt.Println(x)
	poly1.a0=x
	var coefs []*big.Int
	for i:=0;i<degree;i++{
		coef,_:=GenerateRandomNumber()//rand.Int(rand.Reader,big.NewInt(1024))
		//fmt.Println(coef)
		coefs=append(coefs,coef)
	}
	poly1.coefficients=coefs
	return poly1
}

//输入x 计算y=polynomial(x)
func getYat(x *big.Int,poly Polynomial)(*big.Int) {
	y:=big.NewInt(0)
	y=poly.a0
	if  x == big.NewInt(0){
		return y
	}
	for i:=0;i<len(poly.coefficients);i++{
		temp:=new(big.Int).Exp(x,big.NewInt(int64(i+1)),nil)
		temp=new(big.Int).Mul(temp,poly.coefficients[i])
		y=new(big.Int).Add(y,temp)
	}
	return y
}

//拉格朗日插值
func lagrangeInterpolate(xpoints []*big.Int,ypoints []*big.Int)(a0 *big.Int){
	x:=big.NewInt(0)
	a0=big.NewInt(0)
	for i:=0;i<len(xpoints);i++{
		temp1:=big.NewInt(1)
		temp2:=big.NewInt(1)
		for j:=0;j<len(xpoints);j++{
			if i!=j{
				temp1.Mul(temp1,new(big.Int).Sub(x,xpoints[j]))
				temp2.Mul(temp2,new(big.Int).Sub(xpoints[i],xpoints[j]))
			}
		}
		temp1.Mul(temp1,ypoints[i])
		a0.Add(a0,new(big.Int).Div(temp1,temp2))
	}
	return
}

//椭圆曲线拉格朗日插值
func ElipticlagrangeInterpolate(xpoints []*big.Int,ypointxs []*big.Int,ypointys []*big.Int)(a0x *big.Int,a0y *big.Int){
	x:=big.NewInt(0)
	for i:=0;i<len(xpoints);i++{
		temp1:=big.NewInt(1)
		temp2:=big.NewInt(1)
		for j:=0;j<len(xpoints);j++{
			if i!=j{
				temp1.Mul(temp1,new(big.Int).Sub(x,xpoints[j]))
				temp2.Mul(temp2,new(big.Int).Sub(xpoints[i],xpoints[j]))
			}
		}
		temp:=new(big.Int).Div(temp1,temp2)
		temp=new(big.Int).Mod(temp,elliptic.P256().Params().N)//new(big.Int).Mod(temp,S256().Params().N)
		if i==0{
			a0x,a0y=elliptic.P256().ScalarMult(ypointxs[i],ypointys[i],temp.Bytes())
			//S256().ScalarMult(ypointxs[i],ypointys[i],temp.Bytes())
			//fmt.Println("yes")
		} else{
			tempx,tempy:=elliptic.P256().ScalarMult(ypointxs[i],ypointys[i],temp.Bytes())
				//S256().ScalarMult(ypointxs[i],ypointys[i],temp.Bytes())
			a0x,a0y=elliptic.P256().Add(tempx,tempy,a0x,a0y)
				//S256().Add(tempx,tempy,a0x,a0y)
		}
	}
	return
}

func getHash(bytes []byte)([]int){
	//hash := sha256.New()
	//输入数据
	//hash.Write([]byte(str))
	//计算哈希值
	//bytes := hash.Sum(nil)
	//将字符串编码为16进制格式,返回字符串
	//hashCode := hex.EncodeToString(bytes)
	//返回哈希值
	//fmt.Println(hashCode)
	dst := make([]int, 0)
	for _, v := range bytes {
		for i := 0; i < 8; i++ {
			move := uint(7 - i)
			dst = append(dst, int((v>>move)&1))
		}
	}
	return dst
}

//
func GenerateRandomNumber()(k *big.Int, err error){
	//return ecdsa.RandFieldElement(S256(), rand.Reader)
	var one = new(big.Int).SetInt64(1)
	params := elliptic.P256().Params()//S256().Params()
	b := make([]byte, params.BitSize/8+8)
	_, err = io.ReadFull(rand.Reader, b)
	if err != nil {
		return
	}

	k = new(big.Int).SetBytes(b)
	n := new(big.Int).Sub(params.N, one)
	k.Mod(k, n)
	k.Add(k, one)
	return
}

// Keccak256 calculates and returns the Keccak256 hash of the input data.
func Keccak256(data ...[]byte) []byte {
	d := sha3.NewLegacyKeccak256()
	for _, b := range data {
		d.Write(b)
	}
	return d.Sum(nil)
}

//判断表是否已经存在
func PathExists(path string) (bool, error) {
	_, err := os.Stat(path)
	if err == nil {
		return true, nil
	}
	if os.IsNotExist(err) {
		return false, nil//错误为文件不存在
	}
	return false, err//别的错误
}

//---------------------------------------------
func read()([]big.Int) {
	file1x, e := os.OpenFile("privList", os.O_RDWR|os.O_APPEND|os.O_CREATE, 0666)
	if e != nil {
		panic(e)
	}
	Reader1 := bufio.NewReader(file1x)
	defer file1x.Close()
	n:=0
	privKeyOrderList:=make([]big.Int,0,20)
	for true{
		y:=new(big.Int)
		n,_=fmt.Fscanln(Reader1,y)
		if(n>0){
			privKeyOrderList=append(privKeyOrderList,*y)
			fmt.Println(y)
		} else{
			break
		}
	}
	return privKeyOrderList
}
func generateTableIfNewPriv(priv *big.Int,n,t int) int{
	privKeyOrderList:=read()
	flag:=true
	index:=-1
	for i := 0; i < len(privKeyOrderList);i++ {
		//fmt.Println(privKeyOrderList[i])
		if(priv.Cmp(&privKeyOrderList[i])==0) {
			flag=false
			index=i
			break
		}

	}
	if flag {
		//在此处generateTable，使用index命名查找表，需要把index传入generateTable
		privKeyOrderList=append(privKeyOrderList,*priv)
		//fmt.Print("new table with index")
		index=len(privKeyOrderList)-1
		generateTableWithIndex(n,t,priv,index)
		//fmt.Println(index)
		file1, e :=os.OpenFile("privList", os.O_RDWR|os.O_APPEND|os.O_CREATE, 0666)
		//file1, e := os.Create("privList")
		if e != nil {
			panic(e)
		}
		writer1 := bufio.NewWriter(file1)
		fmt.Fprintln(writer1,priv)
		writer1.Flush()
		file1.Close()
	} else {
		//使用index访问已创建的查找表
		//fmt.Print("old table with index")
		//fmt.Println(index)
	}
	return index;
}


//读取配置文件，文件分别存放n,t
func ReadLineTxt(fileName string) ([]int, error) {
	f, err := os.Open(fileName)
	var nameList []int
	if err != nil {
		log.Println("Open File Error:", err)
		return nil, err
	}
	buf := bufio.NewReader(f)
	for {
		line, err := buf.ReadString('\n')
		line = strings.TrimSpace(line)
		num,_:= strconv.Atoi(line)
		if len(line) > 0 {
			nameList = append(nameList, num)
			//g.Tasks <- line
		}
		if err != nil {
			if err == io.EOF {
				log.Println("Read File Finish")
				//close(g.Tasks)
				return nameList, nil
			}
			log.Println("Read File Error:", err)
			return nil, err
		}
	}
	return nil, err
}