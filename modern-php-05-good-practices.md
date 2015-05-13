# 前言
* 本章節示範代碼較多，請先下載[本書 code example](https://github.com/codeguy/modern-php)。
* 把 Timezone 全部修改為 Asia/Taipei 來練習會比較有感覺。
* 補充：在 Sublime Text 環境下 build PHP

### 本章上半場探討這3大主題的良好實踐方式：
* Sanitize, Validate, and Escape
* Passwords
* Dates, Times, and Time Zones

>(2015/5/7 @Laradiner)


# Sanitize,Validate, and Escape （過濾、驗證、跳脫）

千萬別相信使用者輸入的資料，包括以下幾種來源：

* `$_GET`
* `$_POST`
* `$_REQUEST`
* `$_COOKIE`
* `$argv`
* `php://stdin`
* `php://input`
* `file_get_contents()`
* `Remote databases`
* `Remote APIs`
* `Data from your clients`

使用者所輸入的任何資料都有可能被注入惡意的 script (不論是故意或不小心)

>良好實踐：Filter input, Escape output.
>
>補充：食安風暴...政府有在過濾嗎？

## 過濾輸入

### 作用
* 跳脫或移除不安全字符
* 安全的第一道防線


### 操作這些資料時要特別注意
* HTML, SQL queries
* 使用者個人資訊 (i.e., email、地址、電話號碼等)

> 這些資料特別有風險，接觸時時時提醒自己要做過濾。

### 示範一段惡意的 script

```
<p>This was a helpful article!</p><script>
window.location.href='http://example.com';
</script>
```


### 過濾 HTML
* 使用 `htmlentities` 函數來將特殊字元 (e.g., &, >, &#x2033;) 轉換成對應的 HTML entity。
* 但是此函數預設不會轉換單引號，而且也不會偵測字串編碼，正確的用法是：
`htmlentities($input, ENT_QUOTES, 'UTF-8');`
* 實際舉例如下：


```php
<?php
$input = '<p><script>alert("You won the Nigerian lottery!");</script></p>'; 
echo htmlentities($input, ENT_QUOTES, 'UTF-8');
```

>良好實踐：
> 
> * [HTML Purifier](http://htmlpurifier.org/) 是更好的選擇。
> * 使用樣版引擎也會自動處理過濾，如 [Twig](http://twig.sensiolabs.org/) , [Blade](http://laravel.com/docs/5.0/templates) 。

千萬別想說自己寫`正規表示式`來過濾，這傢伙可是又慢又複雜，而且有很大的安全疑慮。

### 過濾 SQL Queries

我們常會從使用者輸入來組 SQL query，像是
`?user=1  // HTTP request query string`

這潛藏著 SQL Injection 的風險，例如：

```php
$sql = sprintf(
    'UPDATE users SET password = "%s" WHERE id = %s',
    $_POST['password'],
    $_GET['id']
);
```


```php
# POST /user?id=1 HTTP/1.1
#    Content-Length: 17
#    Content-Type: application/x-www-form-urlencoded
#    password=abc";--
```

直接一個偽造的請求，輸入惡意字串，讓後面字串被註解掉，即可將所有密碼修改為 abc (驚!)

註：多數資料庫將 `--` 視為註解。

>良好實踐：使用 [PDO](http://php.net/manual/en/book.pdo.php) 與 PDO statements 來處理 SQL Query。
>註：Laravel 的 ORM(Eloquent) 底層就是使用 PDO。

### 過濾個人資訊相關格式
使用者資訊通常包含 email、電話、地址等資訊。

PHP 提供 `filter_var()` and `filter_input()` 函數來過濾這些輸入的格式。

過濾 Email

```php
<?php
$email = 'john@example.com';
$emailSafe = filter_var($email, FILTER_SANITIZE_EMAIL);
```

過濾 ASCII 字符

```php
<?php
$string = "\nIñtërnâtiônàlizætiøn\t"; $safeString = filter_var(
    $string,
    FILTER_SANITIZE_STRING,
    FILTER_FLAG_STRIP_LOW|FILTER_FLAG_ENCODE_HIGH
);
```


### PHP 內建的 Sanitize input
* `filter_var / filter_var_array`
* `filter_input / filter_input_array`
* [瞭解更多 filter_var() 函數](http://php.net/manual/en/function.filter-var.php)
* 參照PHP官網：[內建的 Sanitize filters](http://php.net/manual/en/filter.filters.sanitize.php)


## Validate Data
驗證資料和過濾資料的差異在於，驗證資料只是確認是否符合預期，而不會進行移除。

PHP 提供 `filter_var()` 函數，搭配對應的驗證格式 `FIL TER_VALIDATE_*` 來進行驗證，支援以下驗證格式：

* `Booleans`
* `emails`
* `floats`
* `integers`
* `IP addresses`
* `regular expressions`
* ...等等

驗證 email 格式的例子：

```php
<?php
$input = 'john@example.com';
$isEmail = filter_var($input, FILTER_VALIDATE_EMAIL); 
if ($isEmail !== false) {
    echo "Success"; 
}else{
    echo "Fail"; 
}
```

>注意! 須注意此函數回傳值，通過回傳原始資料，不通過回傳 false

由於 `filter_var()` 內建的驗證格式不夠多，可以在安裝以下套件：

[aura/filter](https://packagist.org/packages/aura/filter)

[respect/validation](https://packagist.org/packages/respect/validation)

[symfony/validator](https://packagist.org/packages/symfony/validator) (Laravel 使用)


>小結論：需要對 input 進行過濾和驗證。

### Escape Output
Output 包含將資料顯示在頁面上，以及回應 API。

如同前面所提到，可用 `htmlentities()` 函數，搭配第二個參數設定為 ENT_QUOTES 才能同時過濾單、雙引號：`htmlentities($input, ENT_QUOTES, 'UTF-8');`

>通常樣版引擎(ex. Twig、Blade) 預設會處理這部分。

-
# Passwords(密碼安全)
* 安全地管理密碼是一件困難的事。
* 大部份開發者並不知道如何安全地處理密碼，使用 MD5/SHA1+salt 就對嗎？(No~No)
* 以下提供幾個準則，並搭配 PHP 內建函式來讓你的網站更安全。

### Never Know User Passwords
* 千萬別明文儲存密碼，萬一 DataBase 被攻破也不會有密碼外洩。
* 知道的越少，對你越安全。The less you know, the safer you are.

### Never Restrict User Passwords
* 不要去限制使用者密碼不能大於多少字元。
* 這將會提示那些有意攻擊你的壞蛋一個參考值，頂多要求密碼至少要多少字元就好。

### Never Email User Passwords
* 使用者忘記密碼時，若是可以藉由 email 重新取回密碼，這代表網站知道我的密碼、我的密碼未被加密。
* [我的密碼沒加密](http://plainpass.com/)
* 曲讓使用者點擊連結重新設定一組密碼(此過程並帶有 token驗證)

>良好實踐：使用者按下忘記密碼，寄email到信箱，讓使用者點擊連結重新設定一組密碼(此過程並帶有 token驗證)

### Hash User Passwords with bcrypt
* 使用者密碼需要經過 hash(雜湊加密) 而非 encrypt(編碼加密)。因為 Encryption 是一種雙向演算法，代表加密後有機會被解密。
* hash 是單向的，hash 後資料相同代表原始資料相同。
* 萬一密碼外洩，這些 hash 過的密碼壞蛋也要花很多時間來處理，或是需要NSA等級的資源來破解。
* 常見的 hash 演算法有：MD5, SHA1, bcrypt, scrypt。
* 可從安全強度、加密速度等指標憑來評估要用哪種 hash 演算法。
* bcrypt：PHP 5.5 預設使用，是目前最安全的加密演算法之一。和 MD5 and SHA1 比起來他的速度最慢(以秒為單位)。
	* BCrypt 犧牲性能來獲得更高的安全性。大致上比 md5/sha1 要慢10000倍，相對的也增加了10000倍的破解成本。[ref](http://blogs.msdn.com/b/lixiong/archive/2011/12/25/md5-sha1-salt-and-bcrypt.aspx)

* 除非你是密碼學專家，否則 hash 的演算法還是不要自己創造。

>良好實踐：請使用 bcrypt 作為你加密的演算法。
>
>Laravel 預設使用 bcrypt 演算法。`Hash::make('secret')`就是它。

### Password Hashing API
* PHP 5.5 提供新的加密函數 `password_hash()` 就是使用 bcrypt 演算法。
* 這是由一位在 Google 服務的 Anthony Ferrara所貢獻。也是 PHP 的大神，作者建議可以訂閱 [Twitter](https://twitter.com/ircmaxell) and read his [blog](http://blog.ircmaxell.com/)。

### Password Hashing API for PHP < 5.5.0
* 可以安裝 Anthony Ferrara’s [ircmaxell/password-compat](https://packagist.org/packages/ircmaxell/password-compat) 套件。


## 示範使用 password hashing API 的兩種情境：
1. 使用者註冊流程
1. 使用者登入流程


## 情境1：使用者註冊流程

請求：

```php
# POST /register.php HTTP/1.1
# Content-Length: 43
# Content-Type: application/x-www-form-urlencoded
# email=john@example.com&password=sekritshhh!
```

```php
<?php
try{
    // Validate email
    $email = filter_input(INPUT_POST, 'email', FILTER_VALIDATE_EMAIL);
    if (!$email) {
        throw new Exception('Invalid email');
    } 

    // Validate password
    $password = filter_input(INPUT_POST, 'password');
    if (!$password || mb_strlen($password) < 8) {
        throw new Exception('Password must contain 8+ characters');
    }

    // Create password hash
    $passwordHash = password_hash(
       $password,
       PASSWORD_DEFAULT,
       ['cost' => 12]
    );

    if ($passwordHash === false) {
        throw new Exception('Password hash failed');
    }

    // Create user account (THIS IS PSUEDO-CODE)
    $user = new User();
    $user->email = $email;
    $user->password_hash = $passwordHash;
    $user->save();

    // Redirect to login page
    header('HTTP/1.1 302 Redirect');
    header('Location: /login.php');

} catch (Exception $e) {
    // Report error
    header('HTTP/1.1 400 Bad request');
    echo $e->getMessage();
}
```

* 使用 `password_hash()`
* cost 預設為 10，每加大1，運算時間大約會多一倍。
* 密碼長度建議使用 `varchar(255)` 儲存

## 情境2：使用者登入流程

請求：

```php
# POST /login.php HTTP/1.1
# Content-Length: 43
# Content-Type: application/x-www-form-urlencoded
# email=john@example.com&password=sekritshhh!
```

```php
<?php
session_start(); 

try{
    // Get email address from request body
    $email = filter_input(INPUT_POST, 'email');

    // Get password from request body
    $password = filter_input(INPUT_POST, 'password');

    // Find account with email address (THIS IS PSUEDO-CODE)
    $user = User::findByEmail($email);

    // Verify password with account password hash
    if (password_verify($password, $user->password_hash) === false) {
        throw new Exception('Invalid password');
    }

    // Re-hash password if necessary(see not below)
    $currentHashAlgorithm = PASSWORD_DEFAULT;
    $currentHashOptions = array('cost' => 15);
    $passwordNeedsRehash = password_needs_rehash(
        $user->password_hash,
        $currentHashAlgorithm,
        $currentHashOptions
    );

    if ($passwordNeedsRehash === true) {
        // Save new password hash (THIS IS PSUEDO-CODE)

        $user->password_hash = password_hash(
            $password,
            $currentHashAlgorithm,
            $currentHashOptions
        );
        $user->save();
    }

    // Save login status to session
    $_SESSION['user_logged_in'] = 'yes';
    $_SESSION['user_email'] = $email;

    // Redirect to profile page
    header('HTTP/1.1 302 Redirect');
    header('Location: /user-profile.php');
} catch (Exception $e) {
    header('HTTP/1.1 401 Unauthorized');
    echo $e->getMessage();
}
```

* 使用 `password_verify()` 驗證密碼正確性
* 使用 `password_needs_rehash()` 檢查密碼是否需要更新(若 hash 值不是最新的才需要更新)

### 密碼安全準則總結以下幾點：

* 密碼需加密儲存。
* 網站知道的越少，對你越安全。
* 不要去限制使用者密碼不能大於多少字元。
* 不提供透過 email 找回密碼，而是使用有時效性的 token 來取代發送密碼。
* 使用 bcrypt 來加密。
* 使用 Password Hashing API(若无法使用 php 5.5 以上，可以使用 [password-compat](https://packagist.org/packages/ircmaxell/password-compat) )

>延伸閱讀：
>
>* 碼書：編碼與解碼的戰爭(The Code Book)
>* 模仿遊戲(The Imitation Game)


-
# Dates, Times, and Time Zones

其實 PHP5.2 就提供好用的 class 像是 `DateTime`, `DateInterval`, and `DateTimeZone` 來處理這些時間相關的操作。

## Set a Default Time Zone

### 設定 Time Zone 的兩個方法：
* 在 php.ini 設定 預設 time zone
`date.timezone = 'America/New_York';`
* 或是在 runtime 使用 `date_default_timezone_set()` 進行設定
完整支援的 time zone 列表詳見
http://php.net/manual/timezones.php


### The DateTime Class
* 可用物件導向的方式來操作 Date Time。

```
$datetime = new DateTime();
```

沒有傳參數到 constructor，預設會以目前的時間。
傳入指定的時間字串(格式請見 http://php.net/manual/ datetime.formdats.php.)

```
$datetime = new DateTime('2014-04-27 5:03 AM');
```

理想上我們要完整指定符合的日期和時間，但實務上通常格式是五花八門，甚至有來自 excel 報表的日期。
這些不符合 php 預期的日期時間格式，可以交給`DateTime::createFromFormat()` 來處理。

此方法允許自訂的格式：
```
$datetime = DateTime::createFromFormat('M j, Y H:i:s', 'Jan 2, 2014 23:04:12');
```

在第一個參數指定格式，第二個參數傳入時間字串
指定格式如同我們熟悉的 `date()` 函數。

(完整格式請參照：http://php.net/manual/datetime.formats.php.)


### The DateInterval Class
* 很常用的必備知識。
* 一個 DateInterval 實體代表：
	* 一個固定的時間長度。例如： two days
	* 一個相對的時間。例如： yesterday
* 可將 `DateInterval` 當作參數傳入 `DateTime` 的 `add()`、`sub()` 方法來操作 `DateTime` 實體的值

另外，`DateInterval` 的 constructor 支援 interval specification 以字串當參數傳入

* interval specification 是一組字串，使用字母 P 設定日期，使用字母 T 設定時間。
* 例如 P2D 代表 two days
* P2DT5H2M 代表 two days, five hours, and two minutes

Interval specification：

* Y (years)
* M (months)
* D (days)
* W (weeks)
* H (hours)
* M (minutes) 
* S (seconds)

舉例：

```
date_default_timezone_set('Asia/Taipei');

// Create DateTime instance
$datetime = new DateTime('2015-05-07 20:00:00');

// Create two weeks interval
$interval = new DateInterval('P2W');

// Modify DateTime instance
$datetime->add($interval);
echo $datetime->format('Y-m-d H:i:s');

```

輸出：

```
2015-05-21 20:00:00
```

DateInterval::createFromDateString('-1 day')

```
date_default_timezone_set('Asia/Taipei');

$dateStart = new \DateTime();
$dateInterval = \DateInterval::createFromDateString('-1 day');
$datePeriod = new \DatePeriod($dateStart, $dateInterval, 3);
foreach ($datePeriod as $date) {
    echo $date->format('Y-m-d'), PHP_EOL;
}
```

輸出：

```
2015-05-07
2015-05-06
2015-05-05
2015-05-04
```


### The DateTimeZone Class
* 處理時區問題一直是很令人頭大。
* `$timezone = new DateTimeZone('America/New_York');`
(完整格式參見)
* DateTime class 的 constructor 第二個參數支援傳入 DateTimeZone instance 

	```
	$timezone = new DateTimeZone('America/New_York');
	$datetime = new DateTime('2014-08-20', $timezone);
	```

* 也可以動態設定

	```
	$datetime->setTimezone(new DateTimeZone('Asia/Hong_Kong'));
	```

* 作者發現處理 timezone 最簡單的方法，存在 DB 的時間統一用 UTC timezone，當要取出顯示時再去指定 timezone
	* 補充，存 int 方法，不用管時區問題，程式也比較單純。缺點大概是人看資料的時候不直覺XD

### The DatePeriod Class
* 有時會需要迭代固定週期的時間，例如行事曆重複的 events，用 DatePeriod 就對了!

* DatePeriod 實體是迭代子(iterator)
傳入三個參數：

	1. DateTime 實體：表示重複開始的日期時間。
	1. DateInterval 實體：表示後來的間隔的時間區間。
	1. 整數：表示重複的次數。

舉例：

```
$period = new DatePeriod($start, $interval, 3);
```
還有選填的第四個參數可以設定，例如，不要包含起始日期，可以傳入 `DatePeriod::EXCLUDE_START_DATE`

舉例：
 
```
$period = new DatePeriod( $start, $interval, 3,              DatePeriod::EXCLUDE_START_DATE );
```                         

實際應用：

```
date_default_timezone_set('Asia/Taipei');

$start = new DateTime();
$interval = new DateInterval('P2D');
$period = new DatePeriod(
    $start,
    $interval,
    3,
    DatePeriod::EXCLUDE_START_DATE
);

foreach ($period as $nextDateTime) {
    echo $nextDateTime->format('Y-m-d H:i:s'), PHP_EOL;
}

```

輸出：

```
2015-05-09 18:56:40
2015-05-11 18:56:40
2015-05-13 18:56:40
```

### The nesbot/carbon Component
經常處理時間問題，可使用 nesbot/carbon 套件。
[第三方套件 Cabon](https://github.com/briannesbitt/Carbon)提供許多好用的方法處理 date time。

-

### 本章下半場探討這4大主題的良好實踐方式：
* Databases
* Multibyte Strings
* Streams
* Errors and Exceptions

>(2015/5/14 @Laradiner)

# Databases 
* PHP 支援多種 DB 連線與連線的介面
* MySQL：mysqli extension，讓 PHP 支援 mysqli_*() 方法
* SQLite3：支援 SQLite3, SQLite3Stmt, and SQLite3Result classes 方法。

>良好實踐：使用 PDO 來操作 Database。

### The PDO Extension
* PHP 提供 native PDO(PHP data Object) extension 來解決此問題。
* 單一介面來操作不同的 SQL DB。
* 雖然 有PDO，但也是要下 SQL，各DB都有自己特有的 SQL，但建議寫 ANSI/ISO SQL 才能通用。

### Database Connections and DSNs
* 在 PHP 內初始化 PDO 實體，來使 PHP 連結 DB。
* 初始化接受的參數稱作 DSN (data source name)
* 提供 DB 連線相關資訊，以 DB driver 名稱作為開頭 (例如 mysql or sqlite) ，並帶有以下資訊(各DB實作有部分差異)：
	* Hostname or IP address
	* Port number
	* Database name
	* Character set

[DSN格式参考](http://php.net/manual/pdo.drivers.php)

```php
<?php 
try {
    $pdo = new PDO( 'mysql:host=127.0.0.1;dbname=books;port=3306;charset=utf8', 'USERNAME','PASSWORD');
} catch (PDOException $e) {
    // Database connection failed
    echo "Database connection failed";
    exit; 
}
```
第二個參數是DB 的 username、 password
舉例 Example 5-18. PDO constructor
建立連線建議使用 PDOException 包住捕捉錯誤。

連線資訊要注意，不要加到版本控制內，更別放到公開環境。

### Keep your database credentials secret
上述範例並不安全，因為將密碼外露，請不要將密碼 hard-code 在 php file 內，因為當 bug 有可能將這些資訊暴露出來。
建議是將帳密這種 credentials, 寫在 config 檔，並且不要放進 版本控制(.gitignore file)，因為有些 repo 是 public。

範例 將帳密放在 settings.php 並放在 project root 目錄，千萬別放到 public 目錄內。
並且使用 include 進來 (p96)

### Prepared Statements(PDOStatement 實體)
我們已經使用 PDO 來與 DB 連線，但還沒結束，我們通常會動態的接收來自 Http 的 Request，
例如藉由輸入的 email 去 DB 尋找使用者。
raw input 可能會被 SQL injection
幸運的是，PDO 讓"淨化輸入" 變得更容易，只要使用 prepared statements and bound parameters

Prepared Statements 就是 PDOStatement 實體，但通常不直接 new 一個來用，而是使用 prepare() 方法，
此方法第一個參數吃 SQL statement string，並回傳 PDOStatement 實體。
舉例
prepare() 方法 搭配 bindValue() 來自動淨化輸入，以避免 SQL injection，
$statement->bindValue(':id', $userId, PDO::PARAM_INT);
第三個參數可以來指定變數的型別，像是 PDO::PARAM_INT 表示整數。
更多 PDO Constants 參考

### Query Results
execute() 方法來執行這些 Prepared Statements。
取得 query results 可以使用  fetch(), fetchAll(), fetchCol umn(), and fetchObject() methods.
有以下的常數可以設定：
PDO::FETCH_ASSOC
fetch() or fetchAll() method 將回傳 associative array. The array keys are database column names.
PDO::FETCH_NUM
fetch() or fetchAll() method 將回傳 numeric array. The array keys are the numeric index of database columns in your query result.
PDO::FETCH_OBJ
fetch() or fetchAll() method 將回傳 object whose properties are database column names

可使用 fetchColumn() method 將回傳單一 column，
Example 5-24. Prepared statement fetch one column, one row at a time as associative array

fetchObject() 方法則是回傳一個物件。


使用 prepare 語句來綁定查詢內容，確保安全性：

```php
<?php
$sql = 'SELECT id FROM users WHERE email = :email';
$statement = $pdo->prepare($sql);
$email = filter_input(INPUT_GET, 'email');
$statement->bindValue(':email', $email); // default string type

$sql = 'SELECT email FROM users WHERE id = :id';
$statement = $pdo->prepare($sql);
$userId = filter_input(INPUT_GET, 'id');
$statement->bindValue(':id', $userId, PDO::PARAM_INT);
```

* PDO::PARAM_BOOL
* PDO::PARAM_NULL
* PDO::PARAM_INT
* PDO::PARAM_STR (default)
    
[一些PDO支援的常數](http://php.net/manual/en/pdo.constants.php)

### Transactions
PDO 也支援 Transactions 操作，
Transactions 
不是每個 DB 都支援 transaction
InnoDB 提供的 transaction
有嚴格資料正確性需求的 Query 使用 Transaction
一組 SQL 要嘛全部可以成功執行，要嘛全部不執行。

像是金流相關系統，一筆購買紀錄可能要修改好幾個表格。用 MyISAM 時必須對好幾個表格使用 TABLE LOCK (仍然有 atomic 問題)，現在可以用 transaction 解決。


-

# Multibyte Strings(p103)
### 何謂 Multibyte Strings？
* 除了英文之外，其他語言多半無法僅用 1 byte 來表示，而需要 Multibyte。
* 而 PHP 內建的字串函數，操作包含  Multibyte string 的 Unicode 編碼的字串，將會產生未預期的結果...

認識 Unicode：[Unicode Consortium](http://www.unicode.org/)

### 如何避免 Multibyte 錯誤
* 安裝 `mbstring` PHP extension。
* 即可使用 `mb_strlen()` 這類函數，取代內建的 `strlen()` 函數。
* 處理 Unicode 編碼的字串，請務必使用 `mbstring` 提供的函數，因為內建的字串函數並不會考慮到 Multibyte 問題。

### Character Encoding
* 目前主流編碼使用 UTF-8。
* 使用 UTF-8 編碼就對了，所有現代的瀏覽器都認識此編碼。
* 字元編碼：一種依照某種格式打包 Unicode 資料的方法。並儲存在記憶體或在 server 與 client 之間傳送。

>小複習：UTF-8是一種可變長度Unicode編碼。使用一至四個bytes作為文字的編碼：一個中文字 3bytes 英文字1bytes
>(Unicode不論中英文都是2bytes，UTF-8算是由此改良而來)

### 認識 Unicode 與 UTF-8
* [the best explanation of Unicode and UTF-8that I’ve seen](https://www.youtube.com/watch?v=MijmeoH9LT4) by Tom Scott
* [writes a nice explanation of characterencodings on his website](http://www.joelonsoftware.com/articles/Unicode.html) by Joel Spolsky

### 處理 Multibyte String 的準則
1. 始終清楚知道資料的編碼。2. 使用 UTF-8 編碼來儲存資料。
3. 輸出資料也是用 UTF-8 編碼。

使用 `mb_detect_encoding()` 來偵測編碼

使用 `mb_convert_encoding()` 來轉換編碼

### Output UTF-8 Data
* 設定 HTML 文件編碼：
	* `<meta charset="UTF-8"/>`
* 設定 PHP 預設輸出 UTF-8 編碼的資料：
	* 在 `php.ini` 設定 `default_charset = "UTF-8";`
	* 將影響 `htmlentities()`,`html_entity_decode()`, `htmlspecialchars()` 和 `mbstring` 等函數預設編碼。
