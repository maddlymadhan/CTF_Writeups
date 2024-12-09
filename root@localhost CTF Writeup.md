## root@localhost CTF Writeup | user: Cr4ckM4st3r

### Category: misc

#### Challenge: Welcome

Welcome to root@localhost! To get started, check the very first announcements made in the system. Hidden within these early messages lies a clue to kickstart your journey.

https://discord.gg/2fhYKYuJ

#### Solution:

Gone to #announcements channel, checked the early messages and got the flag
`Flag: root@localhost{W3lc0m3_T0_r00t@l0c4lh3l1!}`

#### Challenge: The Great Login Heist

In a daring attempt at digital mischief, a crafty threat actor tried to break into Cybertown Tech Solutions' secure web interface. Their sneaky login attempts were caught red-handed in a PCAP file, thanks to our vigilant network monitoring.

flag format :root@localhost{username_password}

#### Solution:

It is a Packet Capture file. So imported it to WireShark. Find out a login made so using Follow HTTP Stream got the username and password. Henceforth got the flag.

![image-20241209132650961](C:\Users\Madhan_B\AppData\Roaming\Typora\typora-user-images\image-20241209132650961.png)

`Flag: root@localhost{Liam_24_P%40ssw0rd!2024}`

#### Challenge: Silent Courier

A mysterious file is being secretly transferred between servers. Your task is to intercept the transfer and uncover the hidden secret. Can you track it down before it's too late?

#### Solution:

It is a Packet Capture file. So imported it to WireShark. Got to know a protected.zip file is downloaded. So used Export Objects -> HTTP to get those packets reassembled as files and downloaded it.

![image-20241209133531480](C:\Users\Madhan_B\AppData\Roaming\Typora\typora-user-images\image-20241209133531480.png)

The zip file password protected so used John to hash it and crack it. Inside the extracted file got the flag.

![image-20241209141033608](C:\Users\Madhan_B\AppData\Roaming\Typora\typora-user-images\image-20241209141033608.png)

`Flag: r00t@localhost{y0u.......................................................................................................................................................}` 

#### Challenge: play with qr

find the correct qr to get flag

#### Solution:

The zip file has 1000 of qr codes. So written a python script to decode the correct qr code and got the flag.

`Flag: root@localhost{7h3_q6_!s_fun}`

### Category: Osint

#### Challenge: Weak

What is one of the most commonly used passwords in the world, often considered weak and insecure?

no need flag format

#### Solution: 

Searched in Google and got the flag

`Flag: 12345678`

#### Challenge: Locate the Bridge

Your task is to find the connection bridge in Rajalakshmi Engineering College using What3Words. Once you locate it, note down the three words assigned to that location. Submit your answer in the following flag format:

flag format:

word1.word2.word3

#### Solution: 

Surfed What3Words and got the flag
`Flag: transmit.headliner.chemistry`

#### Challenge: Find the Lab

In this challenge, your mission is to locate the Idea Lab in Rajalakshmi Engineering College using What3Words. Navigate to the specific location, and retrieve the three words corresponding to it.

Submit the flag in this format:

word1.word2.word3

#### Solution: 

Surfed What3Words and got the flag
`Flag: narrowest.parsnips.chills``

#### Challenge: The Magnetic Epicenter

A certain point in Tamil Nadu is often considered to align closely with the Earth's magnetic equator. Your task is to locate this point and retrieve its what3words address

#### Solution: 

Surfed Google and find out the place is Nataraja Temple, Chidambaram. Then Surfed What3Words and got the flag.
`Flag: flirts.fizzled.rectangular`

#### Challenge: Find the ranch

Identify the location based on the provided coordinates.

Note: That there is no flag format for this challenge.

Example Flag: Rec_Boys_Hostel

#### Solution: 

Used exiftool to got the GPS Position and used the co-ordinates to find the place. In the place got a ranch bridge name and got the flag.

`Flag: Big_River_Ranch`

#### Challenge: The Cyber Sentinels Hunt

The Cyber Sentinels have left a trail of breadcrumbs across the web. Your mission is to follow their digital footprints across Instagram, LinkedIn, and Discord to uncover the flag hidden in three parts. Are you ready to decode their secrets?

#### Solution: 

Surfed their Social Media Handles and got the three parts of flag that is encoded with Base64. So decode them and got the flag

`Flag: r00t@localhost{OS1nT_Cha1n3d_To_Th3_W3b}`

### Category: Stego

#### Challenge: Echo of Time

You found an audio file named ab Somewhere within this audio lies a crucial piece of information: a year that marks a significant event. Extract the year hidden in the audio using steganography techniques.

flag format:r00t@localhost{****}

#### Solution: 

Imported the file to Audacity. Viewed it in Spectogram View and Got the flag.

`Flag: :r00t@localhost{2025}`

#### Challenge: Hidden Truth

A hidden message lies concealed within a jumble of characters and numbers. Can you crack the code and reveal the secret? The mystery is waiting for you to uncover it.

#### Solution: 

Used exiftool and got a Base64 encoded string in it. Decoded it and got the flag.

![image-20241209144927159](C:\Users\Madhan_B\AppData\Roaming\Typora\typora-user-images\image-20241209144927159.png)

`Flag: root@localhost{C0ngr@t$_Y0u_F0und_Th3_Myst3ry_N0w}`

#### Challenge: Pixel Secrets

Decode the hidden message embedded in this image. Use steganographic techniques to uncover the flag that lies beneath the pixels!

Attached File: steg1.jpg

Attached File: password.txt

#### Solution: 

Written a script to brute force steghide with the wordlist provided.

`./steghide_bruteforce.sh steg1.jpg password.txt`

![image-20241209174248829](C:\Users\Madhan_B\AppData\Roaming\Typora\typora-user-images\image-20241209174248829.png)

Got it the password and extracted with steghide. And got the flag

![image-20241209180816102](C:\Users\Madhan_B\AppData\Roaming\Typora\typora-user-images\image-20241209180816102.png)

`Flag: root@localhost{H1dd3n_M3ss4g3_F0und}`

#### Challenge: Secret Stash

In a charming old bookstore, an artist’s illustration graces the cover of a vintage volume. The artwork seems like a beautiful enigma, with intricate details and hidden symbols. Among the various elements, one particular design element holds a clue that leads to a hidden archive within the book. The true prize, a coveted flag, rests safely inside a concealed digital treasure. To uncover the secret, examine the image closely and uncover the secret passage to the zip file within.

Attached File: steg2_pass.txt

Attached File: steg2.jpg

#### Solution: 

Again used that script and got the password `UnlockTheImage!`

And get zip file. Used zip2john to hash the zip and provided it to the john and got the password to extract it. 

Opened the flag.txt and got the flag.

![image-20241209182052086](C:\Users\Madhan_B\AppData\Roaming\Typora\typora-user-images\image-20241209182052086.png)

`Flag: root@localhost{SecureByDesign!2024}`

#### Category: Web

#### Challenge: Easy-Web_challenge

***To Login This Page And Get Flag**

https://web-chall-ten.vercel.app/

#### Solution: 

In the login page, Go to inspect, go to script.js and got a Base64 encoded string. Decoded it and got the flag.

`Flag: root@localhost{The_web_chall_is_easy}`

#### Challenge: Mini Vulnerable Compiler

In this challenge, you have access to a simple online compiler that executes Python code. The code you submit is run on the server, and your goal is to exploit this vulnerability to retrieve the secret flag

https://minicompiler.onrender.com/

#### Solution: 

In this the compiler supports OS Command Injection. So written a python script and got the flag

![image-20241209150211063](C:\Users\Madhan_B\AppData\Roaming\Typora\typora-user-images\image-20241209150211063.png)

`import os`

`os.system("cat flag.txt")` 

`Flag: r00t@locahost{mini_compiler_pwn}`

#### Challenge: iDoor: The Secret Portal

The 'iDoor' web challenge presents a secure access system with an interface that resembles a CCTF camera page. It tests your skills in web exploitation and security analysis.

Note:Its Make Some time start instance

https://idoor-1.onrender.com/?camera=f5ca38f748a1d6eaf726b8a42fb575c3c71f1864a8143301782de13da2d9202b

#### Solution: 

In the url found it is encoded by SHA-256. So generate a list of SHA-256 encoded strings for number 0 to 50 and used Burp Suite to brute force it. Got it at 0 itself and got the flag.

![image-20241209151118111](C:\Users\Madhan_B\AppData\Roaming\Typora\typora-user-images\image-20241209151118111.png)

`Flag: root@localhost{770a058a80a9bca0a87c3e2ebe1ee9b2}`

#### Challenge: XSS vulnerability

**"Find and exploit the XSS vulnerability "**

https://xss-j4in.onrender.com/

#### Solution: 

Hop into that site, used `img src="invalid.jpg" onerror="alert('XSS')">` in the search field. It got reflected and got the flag.

![image-20241209151603311](C:\Users\Madhan_B\AppData\Roaming\Typora\typora-user-images\image-20241209151603311.png)

`Flag: root@localhost{Byp4ss_Sanitiz3r_123}`

#### Challenge: jwt

You’ve logged into a web app with `demo:demo`, but it’s got more holes than Swiss cheese. Your job: find a way to exploit its weak security, escalate your privileges, and sneak into restricted areas. Can you prove the app’s defenses are a joke?

https://web2-k7a3.onrender.com/

#### Solution: 

Logined with username and password as demo: demo and got the token of it 
When using the burp suite found the key to be 'lol' in the potential issues tab.

Used this website and decoded the token.

![image-20241209204819547](C:\Users\Madhan_B\AppData\Roaming\Typora\typora-user-images\image-20241209204819547.png)

 Modified the user as root which i got in the source code of the home page using inspect.

![image-20241209204856478](C:\Users\Madhan_B\AppData\Roaming\Typora\typora-user-images\image-20241209204856478.png)

So Replaced the token with this and got the flag

`Flag: root@localhost{P@ssw0rDS_r_0pti0n4l}`

#### Category: Crypto

#### Challenge: Decode The Hex Value

72 6f 6f 74 40 6c 6f 63 61 6c 68 6f 73 74 7b 54 68 65 5f 48 65 78 5f 76 61 6c 75 65 5f 69 73 5f 33 34 33 33 66 7d

#### Solution: 

Used dcode.fr and Identified the Cipher 

Cipher: ASCII Code

Decode it and Got the flag.

`Flag: root@localhost{The_Hex_value_is_3433f}`

#### Challenge: Route 47

In a world where money was a mess, Sarah stumbled upon Route 47—a top-secret crypto highway to a new world of wealth. With nothing but a mysterious code.

Code : `C@@Eo=@42=9@DEL*@F08@E0E9607=280FD:?80C@EcfN`

#### Solution: 

From clue guess it. 

Cipher: ROT47

Decode it and Got the flag.

`Flag: root@localhost{You_got_the_flag_using_rot47}`

#### Challenge: The Rail Conductor's Secret

As a rail conductor for the ancient Conclave, you've stumbled upon a mysterious train schedule, encrypted to protect the ultimate secret. The clue is simple: "To reach your destination, follow the rails on Track 24 leads to the secret!"

Decode the given string to reveal the flag:

> li_4WR4_y3sh_TL{et4sdo_hTl0a_cTohl3@_tH030rrt}

#### Solution: 

From the clue guessed it.

Cipher: Rail Fence

Decode it with key  24 from clue and offset 24. Got a string. Reversed it and got the flag.

`Flag: r00t@localhost{Th3_R4il_W4ys_Le4d_T0_Th3_H3rt}`

#### Challenge: Byte Buster

++++++++++[>+>+++>+++++++>++++++++++<<<<-]>>>>++++++++++++++.---..+++++.<------.>--------.+++.------------.--.+++++++++++.----.+++++++.++++.+.+++++++.<+++.<++++++++++++++++++.>>-----------------------.<<+++.>.>++++++++++++++.<<+.>>---------------.++++++++.<<-.>>+++++++.<<------------------.+++++++++++++++++.--.++.++.>>+++++++++++.

#### Solution: 

Used dcode.fr and Identified the Cipher 

Cipher: Brainfuck

Decode it and Got the flag.

`Flag: root@localhost{C0d3Cr4ck3r!2024}`

#### Challenge: Feed back

Thank you for participating in our CTF challenge! We’d love to hear your thoughts and improve the experience for future participants. Please take a moment to fill out this form.

https://docs.google.com/forms/d/e/1FAIpQLSdTgzrla-GGUQhe-KS5yyBXdacCHiRwFJfZ7lHrnrkoRHXU-Q/viewform

#### Solution: 

Filled the GForm and in the response confirm page got the flag.

`Flag: r00t@localhost{Th@nk_Y0u_F3edB@ck_R3c4ivEd!!}`

#### Category: Forensic

#### Challenge: Decrypting the Ransom: Malicious DOCM Analysis

A challenge where the goal was to analyze a malicious DOCM file, extract the encryption key from the ransomware, and decrypt the encrypted data.

Attached File: Flie.dcom

#### Solution: 

Used olevba tool to extract its information 

![image-20241209203035144](C:\Users\Madhan_B\AppData\Roaming\Typora\typora-user-images\image-20241209203035144.png)

There is string encoded with Base64. Decoded it and got the flag.

`Flag: root@localhost{m4cr0s_r_d4ng3r0us}`

#### Challenge: fsociety Takeover

Elliot Alderson has left traces of his work while hacking E Corp. Your mission is to uncover the three hidden keys on this machine, each representinga step in his plan.

Rules:

1. Find all three keys and document your steps.
2. Include a timestamp screenshot of the keys with your machine's local time.
3. Submit your write-up through a Discord ticket in the #support channel.

A flag will be provided upon verification. Good luck, hackers—society needs you!

Attached File: [mrRobot](https://drive.google.com/file/d/1f05vox1SJSSKho0wMqe3xRTIsJxNtPEI/view?usp=sharing).ova

#### Solution:

Installed the virutal machine file to my system. While installing found the os is wordpress-4.3.1-0-ubuntu-14.04. I need to find the ip of that vm.

So first i find my ip.

![image-20241209183720038](C:\Users\Madhan_B\AppData\Roaming\Typora\typora-user-images\image-20241209183720038.png)

Then scanned the full network and got the ip address 192.168.1.40

![image-20241209183846773](C:\Users\Madhan_B\AppData\Roaming\Typora\typora-user-images\image-20241209183846773.png)

Then used gobuster and find the directories for status success

and go the robots location and got the first key and a dic file

![image-20241209203513552](C:\Users\Madhan_B\AppData\Roaming\Typora\typora-user-images\image-20241209203513552.png)

`Key 1: 073403c8a58a1f80d943455fb30724b9`

It used wordpress so i directed to the admin page http://192.168.1.40/wp-login 
It contained may duplicates, so i removed it and sorted it and performed brute force on it.

![image-20241209210037703](C:\Users\Madhan_B\AppData\Roaming\Typora\typora-user-images\image-20241209210037703.png)

and got the hit.

![image-20241209210105571](C:\Users\Madhan_B\AppData\Roaming\Typora\typora-user-images\image-20241209210105571.png)

Login into the wordpress admin page and changed a 404.php file for reverse shell script and listened to it 
![image-20241209210424191](C:\Users\Madhan_B\AppData\Roaming\Typora\typora-user-images\image-20241209210424191.png)

Then used netcat to listen it. 

![image-20241209212447366](C:\Users\Madhan_B\AppData\Roaming\Typora\typora-user-images\image-20241209212447366.png)

In password.raw-md5 we got a MD5 string and decode it.

![image-20241209211748679](C:\Users\Madhan_B\AppData\Roaming\Typora\typora-user-images\image-20241209211748679.png)

Used this password and login to robot and got the key 2

![image-20241209212737889](C:\Users\Madhan_B\AppData\Roaming\Typora\typora-user-images\image-20241209212737889.png)

`Key 2: 822c73956184f694993bede3eb39f959` 

Then checked the permission for that user and got nmap and run in interactive mode.

![image-20241209212906287](C:\Users\Madhan_B\AppData\Roaming\Typora\typora-user-images\image-20241209212906287.png)

And then surfed into it and got the third key

![image-20241209212949193](C:\Users\Madhan_B\AppData\Roaming\Typora\typora-user-images\image-20241209212949193.png)

`Key 3: 04787ddef27c3dee1ee161b21670b4e4`

And gained points from the ctf admin.

#### Category: Rev

#### Challenge: Reverse

Attached File: chall2

#### Solution:

It is an executable file needs a correct input. So Used Ghidra to Analyze it and got a function evaluates the input string. Got the string to be AB12CD34EF56GH7

![image-20241209193317876](C:\Users\Madhan_B\AppData\Roaming\Typora\typora-user-images\image-20241209193317876.png)

It gives the output and got the flag

![image-20241209193909789](C:\Users\Madhan_B\AppData\Roaming\Typora\typora-user-images\image-20241209193909789.png)

`Flag: root@localhost{AB12CD34EF56GH7}`

#### Solution:

#### Challenge: Enigma Unveiled

Your mission is to crack open this compiled binary and uncover the hidden flag. Dive into the code, decode the mysteries, and reveal what’s been cleverly concealed.

flag format: root@localhost{*************************}

Attached File: rev1

#### Solution:

It is also an executable file but requires password.

![image-20241209194139867](C:\Users\Madhan_B\AppData\Roaming\Typora\typora-user-images\image-20241209194139867.png)

Used Ghidra and founded that password encoded with Base64. 

![image-20241209194440709](C:\Users\Madhan_B\AppData\Roaming\Typora\typora-user-images\image-20241209194440709.png)

Decode it and got the password. Hence its the flag and got the flag.

`Flag: root@localhost{f0r_y0ur_5ec0nd_le55on_unbase64_4ll_7h3_7h1ng5}`

#### Category: Cloud Security

#### Challenge: Misconfigured Bucket

A cloud storage bucket named **ctf-flag-bucket** has been discovered. It seems the owner made some configuration mistakes, leaving it vulnerable.

Your task:

1. Identify the bucket's contents. 2)Locate a file named somerandomename.txt inside the bucket. 3)Extract the flag from the file.

Hints:

The bucket is publicly accessible via cloud storage APIs or a web interface. Familiarize yourself with common tools like awscli, s3browser, or curl for exploring storage buckets.

#### Solution:

Go to that bucket link and got a text file in it.

![image-20241209154807116](C:\Users\Madhan_B\AppData\Roaming\Typora\typora-user-images\image-20241209154807116.png)

Open the text file and got the flag

![image-20241209154901197](C:\Users\Madhan_B\AppData\Roaming\Typora\typora-user-images\image-20241209154901197.png)

`Flag: r00t@localhost{wh0_st0le_my_c00kies}`

#### Challenge: S3crets

Within an open vault of data, a hidden key awaits—seek through the files to uncover the secret flag.

bucketname: rootatlocalhost

https://rootatlocalhost.s3.us-east-1.amazonaws.com/index.html

#### Solution:

Go to that bucket link and got a text file in it.

![image-20241209155609211](C:\Users\Madhan_B\AppData\Roaming\Typora\typora-user-images\image-20241209155609211.png)

Open the text file and got the flag

![image-20241209155615678](C:\Users\Madhan_B\AppData\Roaming\Typora\typora-user-images\image-20241209155615678.png)

`Flag: r00t@localhost{s3_bucket_leaked_data}`

#### Challenge: Cloud Infiltration

Elena, the lead security officer at TechCore Solutions, suspects a vulnerability in their cloud infrastructure. She’s given you limited access to their system to investigate. Your mission: navigate the cloud terminal, uncover hidden files, and retrieve the flag.

The first to find it will earn a special reward. Can you outsmart their defenses and crack the system?

https://insanecloud.s3.us-east-1.amazonaws.com/aws.html

#### Solution:

Hopped into that bucket link. And it used SSM service and got the keys.

![image-20241209155932463](C:\Users\Madhan_B\AppData\Roaming\Typora\typora-user-images\image-20241209155932463.png)

Used aws cli and configure it with that keys

aws ec2 describe-instances

aws ssm start-session --target <instance-id>

used sudo chmod +rwx flag.txt

And got the flag 





`Flag: r00t@localhost{c10udy_d4ys_4re_fun_1f_cr34tiv3_th1ngs_t0_d0_happens}`











