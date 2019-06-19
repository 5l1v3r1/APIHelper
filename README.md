# APIHelper
- Added AutoSign with checkbox to sign the data when do EncryptMe.
- Implemented AES enc/dec and custom sign method.

## Thanks and Credit to:
This plugin is sort of a enforcing the original `aes-payloads`[https://github.com/portswigger/aes-payloads] of PortSwigger, which is an extender for AES enc/dec and it's working on seperate TAB and Intruder.

This enforcement is to add context menu in Repeater to call enc/dec, so that you don't have to copy/past around during testing.

This is also improved by organizing the code using Maven way, so you can just `mvn install` to get the working jar file.

## About SignME! function
This is of a custom requirement, you have to re-implement yours if you need this to work correctly. The code shows itself the way.

## Usage

1. convert AES key to Hex String

    Many ways to do this, like HackBar
2. Config AES in the APIHelper-AES Tab

    Note: Mode "AES" will use `SecureRandom` which may need you to change the source code of `SignUtil.java`.
    ```java
    SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
	random.setSeed(key.getBytes());
    ```
3. AutoSign

    With `Enable auto SignMe while do EncryptMe using custom sign method` checked, you can use your customized sign method to sign the data. Need to modify the source code to your need.
    You can disable this checkbox if you don't need it.
4. Only show DecryptMe when context is in Response of Request, or View mode.

## Install
1. clone the source

    `git clone https://github.com/mr-m0nst3r/APIHelper`
2. clean and package

    cd to the folder and do:
    `mvn clean install`
3. add to burp

    open Burp Extender, add, select `./target/APHHelper-0.0.2-SNAPSHOT-jar-with-dependencies.jar`

Happy hacking!