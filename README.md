# Writeup-Cookie-Arena-CTF

## WEB

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


