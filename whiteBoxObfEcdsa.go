package sw

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"math/big"
	"os"
	"strconv"
)

//生成密钥(x,P)
func keygen()  (*ecdsa.PrivateKey, error){
	return ecdsa.GenerateKey(elliptic.P256(),rand.Reader)
}

//生成查找表等价于whitboxobf
func generateTable(n ,t int,privk *ecdsa.PrivateKey)  {
	fmt.Println("generating table!!!")
	//s256曲线的阶
	order := elliptic.P256().Params().N//S256().Params().N

	file1, e := os.Create("T1")
	if e != nil {
		panic(e)
	}
	writer1 := bufio.NewWriter(file1)
	file2, e := os.Create("T2")
	if e != nil {
		panic(e)
	}
	writer2 := bufio.NewWriter(file2)
	file3, e := os.Create("T3")
	if e != nil {
		panic(e)
	}
	writer3 := bufio.NewWriter(file3)
	file4, e := os.Create("T4")
	if e != nil {
		panic(e)
	}
	writer4 := bufio.NewWriter(file4)
	//file5, e := os.Create("T5")
	//if e != nil {
	//	panic(e)
	//}
	//writer5 := bufio.NewWriter(file5)

	//公钥写入T5（可省略）
	//_,_ = fmt.Fprintln(writer5,privk.PublicKey.X);
	//_,_ = fmt.Fprintln(writer5,privk.PublicKey.Y);
	//writer5.Flush()
	//file5.Close()

	//用来表示我们要生成n个点
	var xpoints []*big.Int
	for i := 0; i < n; i++ {
		x := big.NewInt(int64(i + 1))
		xpoints = append(xpoints, x)
	}

	var aypoints []*big.Int

	//关于a的t阶梯多项式
	poly2 := generatePolynomial(t)
	for i := 0; i < n; i++ {
		y := getYat(xpoints[i], poly2)
		aypoints = append(aypoints, y)
	}
	//存放对应的(y mod order)
	var ay2points []*big.Int
	for i := 0; i < n; i++ {
		y := new(big.Int).Mod(aypoints[i], order)
		ay2points = append(ay2points, y)
	}

	var xypoints []*big.Int
	poly4 := generateUniquePolynomial(t,privk.D)
	for i := 0; i < n; i++ {
		y := getYat(xpoints[i], poly4)
		xypoints = append(xypoints, y)
	}

	for j:=0;j<n;j++{
		//生成k的份额 k_i^j
		var kypoints []*big.Int
		poly1 := generatePolynomial(t)
		for i := 0; i < n; i++ {
			y := getYat(xpoints[i], poly1)
			kypoints = append(kypoints, y)
			yt:=new(big.Int).Mod(y,order)
			fmt.Fprintln(writer1,yt)
		}

		//生成b的份额 b_i^j
		var bypoints []*big.Int
		poly3 := generateZeroPolynomial(2 * t)
		for i := 0; i < n; i++ {
			y := getYat(xpoints[i], poly3)
			bypoints = append(bypoints, y)
		}
		//生成a_ik_i^j+b_i^j
		var kaAddbypoints []*big.Int
		for i := 0; i < n; i++ {
			y := new(big.Int).Mul(kypoints[i], aypoints[i])
			y = new(big.Int).Add(y, bypoints[i])
			kaAddbypoints = append(kaAddbypoints, y)
			yt:=new(big.Int).Mod(y,order)
			fmt.Fprintln(writer2,yt)
		}

		//生成c_i^j
		var cypoints []*big.Int
		poly5 := generateZeroPolynomial(2 * t)
		for i := 0; i < n; i++ {
			y := getYat(xpoints[i], poly5)
			cypoints = append(cypoints, y)
		}
		//生成k_i^jx_i+c_i^j
		var kxAddcypoints []*big.Int
		for i := 0; i < n; i++ {
			y := new(big.Int).Mul(kypoints[i], xypoints[i])
			y = new(big.Int).Add(y, cypoints[i])
			kxAddcypoints = append(kxAddcypoints, y)
			yt:=new(big.Int).Mod(y,order)
			fmt.Fprintln(writer3,yt)
		}
	}

	//生成aG的表T4
	var aypointxs []*big.Int
	var aypointys []*big.Int
	for i := 0; i < n; i++ {
		//ai:=new(big.Int).Mod(aypoints[i],S256().Params().N)
		aix, aiy := elliptic.P256().ScalarBaseMult(ay2points[i].Bytes())
		//S256().ScalarBaseMult(ay2points[i].Bytes())
		fmt.Fprintln(writer4,aix)
		fmt.Fprintln(writer4,aiy)
		aypointxs = append(aypointxs, aix)
		aypointys = append(aypointys, aiy)
	}
	writer1.Flush()
	file1.Close()
	writer2.Flush()
	file2.Close()
	writer3.Flush()
	file3.Close()
	writer4.Flush()
	file4.Close()
	return
}



//WBObfECDSASign
func WBObfECDSASign(message []byte,n int) (r,s *big.Int) {
	order := elliptic.P256().Params().N

	h := sha256.New()
	h.Write(message)
	msg := h.Sum(nil)


	dst:=getHash(msg)
	//mBig := new(big.Int).SetBytes(msg)
	mBig := new(big.Int).SetBytes(message)

	file1x, e := os.Open("T1")
	if e != nil {
		panic(e)
	}
	Reader1 := bufio.NewReader(file1x)
	defer file1x.Close()
	file2x, e := os.Open("T2")
	if e != nil {
		panic(e)
	}
	Reader2 := bufio.NewReader(file2x)
	defer file2x.Close()
	file3x, e := os.Open("T3")
	if e != nil {
		panic(e)
	}
	Reader3 := bufio.NewReader(file3x)
	defer file3x.Close()
	file4x, e := os.Open("T4")
	if e != nil {
		panic(e)
	}
	Reader4 := bufio.NewReader(file4x)
	defer file3x.Close()

	//
	var xpoints []*big.Int
	for i := 0; i < n; i++ {
		x := big.NewInt(int64(i + 1))
		xpoints = append(xpoints, x)
	}
	var kytpoints []*big.Int
	var katpoints []*big.Int
	var kxtpoints []*big.Int
	var aypointxts []*big.Int
	var aypointyts []*big.Int
	for i := 0; i < n; i++ {
		kytpoints=append(kytpoints,big.NewInt(0))
		katpoints=append(katpoints,big.NewInt(0))
		kxtpoints=append(kxtpoints,big.NewInt(0))
		aypointxts=append(aypointxts,big.NewInt(0))
		aypointyts=append(aypointyts,big.NewInt(0))
	}
	for i:=0;i<n;i++{
		fmt.Fscanln(Reader4,aypointxts[i])
		fmt.Fscanln(Reader4,aypointyts[i])
	}
	for j:=0;j<n;j++{
		if dst[j]==1{
			for i:=0;i<n;i++{
				k:=new(big.Int)
				ka:=new(big.Int)
				kx:=new(big.Int)
				fmt.Fscanln(Reader1,k)
				fmt.Fscanln(Reader2,ka)
				fmt.Fscanln(Reader3,kx)
				k=new(big.Int).Add(k,kytpoints[i])
				ka=new(big.Int).Add(ka,katpoints[i])
				kx=new(big.Int).Add(kx,kxtpoints[i])
				k=new(big.Int).Mod(k,order)
				ka=new(big.Int).Mod(ka,order)
				kx=new(big.Int).Mod(kx,order)
				kytpoints[i]=k
				katpoints[i]=ka
				kxtpoints[i]=kx
			}
		}else{
			for i:=0;i<n;i++{
				k:=new(big.Int)
				ka:=new(big.Int)
				kx:=new(big.Int)
				fmt.Fscanln(Reader1,k)
				fmt.Fscanln(Reader2,ka)
				fmt.Fscanln(Reader3,kx)
			}
		}

	}

	//
	kat := lagrangeInterpolate(xpoints, katpoints)
	aGx, aGy := ElipticlagrangeInterpolate(xpoints, aypointxts, aypointyts)
	uInvt := new(big.Int).ModInverse(kat, order)
	Rxt, _ := elliptic.P256().ScalarMult(aGx,aGy,uInvt.Bytes())//S256().ScalarMult(aGx, aGy, uInvt.Bytes())
	r = new(big.Int).Mod(Rxt,order)
	//恢复s
	var stpoints []*big.Int
	for i := 0; i < n; i++ {
		y := new(big.Int).Mul(kytpoints[i], mBig)
		temp:= new(big.Int).Mul(kxtpoints[i], Rxt)
		y = new(big.Int).Add(y, temp)
		y=new(big.Int).Mod(y,order)
		stpoints = append(stpoints, y)
	}
	s = new(big.Int).Mod(lagrangeInterpolate(xpoints, stpoints), order)

	return r,s


}

//-------------------------------------------------------------------------------------------------------

func generateTableWithIndex(n ,t int,D *big.Int,tableIndex int)  {
	//fmt.Println("generating table!!!")
	//s256曲线的阶
	order := elliptic.P256().Params().N//S256().Params().N

	file1, e := os.Create("T1_"+strconv.Itoa(tableIndex))
	if e != nil {
		panic(e)
	}
	writer1 := bufio.NewWriter(file1)
	file2, e := os.Create("T2_"+strconv.Itoa(tableIndex))
	if e != nil {
		panic(e)
	}
	writer2 := bufio.NewWriter(file2)
	file3, e := os.Create("T3_"+strconv.Itoa(tableIndex))
	if e != nil {
		panic(e)
	}
	writer3 := bufio.NewWriter(file3)
	file4, e := os.Create("T4_"+strconv.Itoa(tableIndex))
	if e != nil {
		panic(e)
	}
	writer4 := bufio.NewWriter(file4)
	//file5, e := os.Create("T5")
	//if e != nil {
	//	panic(e)
	//}
	//writer5 := bufio.NewWriter(file5)

	//公钥写入T5（可省略）
	//_,_ = fmt.Fprintln(writer5,privk.PublicKey.X);
	//_,_ = fmt.Fprintln(writer5,privk.PublicKey.Y);
	//writer5.Flush()
	//file5.Close()

	//用来表示我们要生成n个点
	var xpoints []*big.Int
	for i := 0; i < n; i++ {
		x := big.NewInt(int64(i + 1))
		xpoints = append(xpoints, x)
	}

	var aypoints []*big.Int

	//关于a的t阶梯多项式
	poly2 := generatePolynomial(t)
	for i := 0; i < n; i++ {
		y := getYat(xpoints[i], poly2)
		aypoints = append(aypoints, y)
	}
	//存放对应的(y mod order)
	var ay2points []*big.Int
	for i := 0; i < n; i++ {
		y := new(big.Int).Mod(aypoints[i], order)
		ay2points = append(ay2points, y)
	}

	var xypoints []*big.Int
	poly4 := generateUniquePolynomial(t,D)
	for i := 0; i < n; i++ {
		y := getYat(xpoints[i], poly4)
		xypoints = append(xypoints, y)
	}

	for j:=0;j<n;j++{
		//生成k的份额 k_i^j
		var kypoints []*big.Int
		poly1 := generatePolynomial(t)
		for i := 0; i < n; i++ {
			y := getYat(xpoints[i], poly1)
			kypoints = append(kypoints, y)
			yt:=new(big.Int).Mod(y,order)
			fmt.Fprintln(writer1,yt)
		}

		//生成b的份额 b_i^j
		var bypoints []*big.Int
		poly3 := generateZeroPolynomial(2 * t)
		for i := 0; i < n; i++ {
			y := getYat(xpoints[i], poly3)
			bypoints = append(bypoints, y)
		}
		//生成a_ik_i^j+b_i^j
		var kaAddbypoints []*big.Int
		for i := 0; i < n; i++ {
			y := new(big.Int).Mul(kypoints[i], aypoints[i])
			y = new(big.Int).Add(y, bypoints[i])
			kaAddbypoints = append(kaAddbypoints, y)
			yt:=new(big.Int).Mod(y,order)
			fmt.Fprintln(writer2,yt)
		}

		//生成c_i^j
		var cypoints []*big.Int
		poly5 := generateZeroPolynomial(2 * t)
		for i := 0; i < n; i++ {
			y := getYat(xpoints[i], poly5)
			cypoints = append(cypoints, y)
		}
		//生成k_i^jx_i+c_i^j
		var kxAddcypoints []*big.Int
		for i := 0; i < n; i++ {
			y := new(big.Int).Mul(kypoints[i], xypoints[i])
			y = new(big.Int).Add(y, cypoints[i])
			kxAddcypoints = append(kxAddcypoints, y)
			yt:=new(big.Int).Mod(y,order)
			fmt.Fprintln(writer3,yt)
		}
	}

	//生成aG的表T4
	var aypointxs []*big.Int
	var aypointys []*big.Int
	for i := 0; i < n; i++ {
		//ai:=new(big.Int).Mod(aypoints[i],S256().Params().N)
		aix, aiy := elliptic.P256().ScalarBaseMult(ay2points[i].Bytes())
		//S256().ScalarBaseMult(ay2points[i].Bytes())
		fmt.Fprintln(writer4,aix)
		fmt.Fprintln(writer4,aiy)
		aypointxs = append(aypointxs, aix)
		aypointys = append(aypointys, aiy)
	}
	writer1.Flush()
	file1.Close()
	writer2.Flush()
	file2.Close()
	writer3.Flush()
	file3.Close()
	writer4.Flush()
	file4.Close()
	return
}

func WBObfECDSASignWithIndex(message []byte,n int,tableIndex int) (r,s *big.Int) {
	order := elliptic.P256().Params().N

	h := sha256.New()
	h.Write(message)
	msg := h.Sum(nil)


	dst:=getHash(msg)
	//mBig := new(big.Int).SetBytes(msg)
	mBig := new(big.Int).SetBytes(message)

	file1x, e := os.Open("T1_"+strconv.Itoa(tableIndex))
	if e != nil {
		panic(e)
	}
	Reader1 := bufio.NewReader(file1x)
	defer file1x.Close()
	file2x, e := os.Open("T2_"+strconv.Itoa(tableIndex))
	if e != nil {
		panic(e)
	}
	Reader2 := bufio.NewReader(file2x)
	defer file2x.Close()
	file3x, e := os.Open("T3_"+strconv.Itoa(tableIndex))
	if e != nil {
		panic(e)
	}
	Reader3 := bufio.NewReader(file3x)
	defer file3x.Close()
	file4x, e := os.Open("T4_"+strconv.Itoa(tableIndex))
	if e != nil {
		panic(e)
	}
	Reader4 := bufio.NewReader(file4x)
	defer file3x.Close()

	//
	var xpoints []*big.Int
	for i := 0; i < n; i++ {
		x := big.NewInt(int64(i + 1))
		xpoints = append(xpoints, x)
	}
	var kytpoints []*big.Int
	var katpoints []*big.Int
	var kxtpoints []*big.Int
	var aypointxts []*big.Int
	var aypointyts []*big.Int
	for i := 0; i < n; i++ {
		kytpoints=append(kytpoints,big.NewInt(0))
		katpoints=append(katpoints,big.NewInt(0))
		kxtpoints=append(kxtpoints,big.NewInt(0))
		aypointxts=append(aypointxts,big.NewInt(0))
		aypointyts=append(aypointyts,big.NewInt(0))
	}
	for i:=0;i<n;i++{
		fmt.Fscanln(Reader4,aypointxts[i])
		fmt.Fscanln(Reader4,aypointyts[i])
	}
	for j:=0;j<n;j++{
		if dst[j]==1{
			for i:=0;i<n;i++{
				k:=new(big.Int)
				ka:=new(big.Int)
				kx:=new(big.Int)
				fmt.Fscanln(Reader1,k)
				fmt.Fscanln(Reader2,ka)
				fmt.Fscanln(Reader3,kx)
				k=new(big.Int).Add(k,kytpoints[i])
				ka=new(big.Int).Add(ka,katpoints[i])
				kx=new(big.Int).Add(kx,kxtpoints[i])
				k=new(big.Int).Mod(k,order)
				ka=new(big.Int).Mod(ka,order)
				kx=new(big.Int).Mod(kx,order)
				kytpoints[i]=k
				katpoints[i]=ka
				kxtpoints[i]=kx
			}
		}else{
			for i:=0;i<n;i++{
				k:=new(big.Int)
				ka:=new(big.Int)
				kx:=new(big.Int)
				fmt.Fscanln(Reader1,k)
				fmt.Fscanln(Reader2,ka)
				fmt.Fscanln(Reader3,kx)
			}
		}

	}

	//
	kat := lagrangeInterpolate(xpoints, katpoints)
	aGx, aGy := ElipticlagrangeInterpolate(xpoints, aypointxts, aypointyts)
	uInvt := new(big.Int).ModInverse(kat, order)
	Rxt, _ := elliptic.P256().ScalarMult(aGx,aGy,uInvt.Bytes())//S256().ScalarMult(aGx, aGy, uInvt.Bytes())
	r = new(big.Int).Mod(Rxt,order)
	//恢复s
	var stpoints []*big.Int
	for i := 0; i < n; i++ {
		y := new(big.Int).Mul(kytpoints[i], mBig)
		temp:= new(big.Int).Mul(kxtpoints[i], Rxt)
		y = new(big.Int).Add(y, temp)
		y=new(big.Int).Mod(y,order)
		stpoints = append(stpoints, y)
	}
	s = new(big.Int).Mod(lagrangeInterpolate(xpoints, stpoints), order)

	return r,s


}