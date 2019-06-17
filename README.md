# APIHelper
Implemented AES enc/dec and custom sign method.

## Thanks and Credit to:
This plugin is sort of a enforcing the original `aes-payloads`[https://github.com/portswigger/aes-payloads] of PortSwigger, which is an extender for AES enc/dec and it's working on seperate TAB and Intruder.

This enforcement is to add context menu in Repeater to call enc/dec, so that you don't have to copy/past around during testing.

This is also improved by organizing the code using Maven way, so you can just `mvn install` to get the working jar file.

## About SignME! function
This is of a custom requirement, you have to re-implement yours if you need this to work correctly. The code shows itself the way.

