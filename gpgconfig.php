<?php 
 // gpgconfig.php : Include file for WEB ENCRYPTION EXTENSION
 // version 3.0    phpmyadmin

    $GPGDIR = "/home/gpg";
    $KEYSELECTION = "yes";
    $KEYEXPORT = "yes";
    $SECRETKEYEXPORT = "yes";
    $KEYCREATION = "yes";
    $KEYSREADONLY = "no";
    //$KEYSREADONLY = "yes";
    $DELETESECRETKEY = "yes";

    $FLEXIBLE = "yes";
    //$ADDPRE = "yes";
    $FORYOUREYESONLY = "yes";

    // Encryption
    $INPUT = "textarea";
    
    // Decryption
    $DECRYPTIONINPUT = "textarea";
    
    // Signature
    $SIGINPUT = "textarea";

    // Verification
    $VERIFYINPUT = "textarea";

    $VERSION = "3.1";

/*
-----BEGIN PGP SIGNED MESSAGE-----
Hash: SHA1

*/

/************************************************************
* Copyright Ralf Senderek, Ireland 2011-2013. (http://senderek.ie)
*
* Update in 2018 by impreza.host (support@impreza.email)
*
* This file is part of the WEB ENCRYPTION EXTENSION (WEE)
* File     : gpgconfig.php
* Version  : 3.0
* License  : GPL-v3
* Signature: To protect the integrity of the source code, this program
*            is signed with the code signing key used by the copyright
*            holder, Ralf Senderek.
* Date     : Thursday, 31 July 2014
* Contact  : Please send enquiries and bug-reports to opensource@senderek.ie
*
* This program is free software: you can redistribute it and/or modify
* it under the terms of the GNU General Public License as published by
* the Free Software Foundation, either version 3 of the License, or
* (at your option) any later version.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
* GNU General Public License for more details.
*
* You should have received a copy of the GNU General Public License
* along with this program.  If not, see <http://www.gnu.org/licenses/>.
*
**************************************************************/

// essential checks (do not remove!)

 if (! isset ($SECURE_CONNECTION)){
     $SECURE_CONNECTION = "yes";
 }

 if (! isset ($APACHE)){
     //$APACHE = 0;
     $APACHE = 48;
 }

  if($_SERVER['HTTPS'] != "on") {
     die ("<h3 class=error>This connection is not secured by SSL. Aborting.</h3>");
 }

 if ((! isset($AUTHREQUIRED)) or ($AUTHREQUIRED == "yes")) {
     require_once 'wee-auth.php';
 }

 // the $GPGDIR may have changed as a result of user authentication in wee-auth.php

 if (! is_dir($GPGDIR)){
     die ("<p><h3 class=error>Directory $GPGDIR does not exist.</h3>");
 } else {
     if (fileowner($GPGDIR) != $APACHE){
         echo "<p>run: chown $APACHE $GPGDIR";
          die("<p><h3 class=error>Directory $GPGDIR is not owned by webserver user</h3>");

     } else {
          /* if (decbin(fileperms($GPGDIR)) != "100000111000000" ) {
               echo "<p>run: chmod 700 $GPGDIR";
               die  ("<p><h3 class=error>Directory $GPGDIR has insecure permissions.</h3>");
          } */
     }
 }


// GLOBAL FUNCTIONS

function unix(String $command):String
{
      // Executing a System Command with output
      $handle = popen("$command 2>&1", 'r');
      $text = fread($handle, 2000000);
      pclose($handle);
      return $text;
}

function unix2(String $command,String $dir):String
{
      // Executing a System Command with very large output but no input
      $rndhandle = fopen("/dev/urandom","r");
      $RND = fread($rndhandle,20);
      fclose($rndhandle);
      $FILENAME = $dir."/".sha1($RND);
      $handle = popen("$command > ".$FILENAME." 2> ".$FILENAME, 'r');
      $res = fread($handle, 20000000);
      pclose($handle);
      $handle = fopen($FILENAME, "r");
      $text = fread($handle,20000000);
      fclose($handle);
      // destroy content of the plain text file
      unix("dd if=/dev/zero of=".$FILENAME." bs=1 count=".strlen($text));
      unix("sync");
      unix("rm ".$FILENAME);
      return $text;
}

function unixpipe(String $command,String $input)
{
      // Executing a System Command with no output to STDOUT but reading $input
      $handle = popen("$command 2>&1", 'w');
      
	  fwrite($handle, $input);
      pclose($handle);
}

function checkinput(String $input,String $mode):String
{
      if ($mode == "none") {
           return $input;
      }
      else {
           if ($mode == "noscript") {
                //return addslashes($input);
                $filter = array('"'=>'', '\\'=>'', '\''=>'', ';'=>'', '('=>'', ')'=>'', '{'=>'', '}'=>'', '$'=>'');
                return strtr($input, $filter);
           }
           if ($mode == "html") {
                return htmlentities($input);
           }
           if ($mode == "url") {
                return rawurlencode($input);
           }
      }
      return "none";
}

if (! isset($INPUT)){
     $INPUT     = "textarea";
}
if (! isset($INPUTNAME)){
     $INPUTNAME = "message";
}
if (! isset($INPUTID)){
     $INPUTID   = "message";
}

if (! isset($ENCRYPTIONTEXTAREA)){
     $ENCRYPTIONTEXTAREA = "messagearea";
}

if (! isset($DECRYPTIONINPUT)){
     $DECRYPTIONINPUT     = "textarea";
}
if (! isset($DECRYPTIONINPUTNAME)){
     $DECRYPTIONINPUTNAME = "message";
}
if (! isset($DECRYPTIONINPUTID)){
     $DECRYPTIONINPUTID   = "message";
}

if (! isset($DECRYPTIONTEXTAREA)){
     $DECRYPTIONTEXTAREA = "messagearea";
}

if (! isset($SIGINPUT)){
     $SIGINPUT     = "textarea";
}
if (! isset($SIGINPUTNAME)){
     $SIGINPUTNAME = "message";
}
if (! isset($SIGINPUTID)){
     $SIGINPUTID   = "message";
}

if (! isset($SIGTEXTAREA)){
     $SIGTEXTAREA = "messagearea";
}

if (! isset($VERIFYINPUT)){
     $VERIFYINPUT     = "textarea";
}
if (! isset($VERIFYINPUTNAME)){
     $VERIFYINPUTNAME = "message";
}
if (! isset($VERIFYINPUTID)){
     $VERIFYINPUTID   = "message";
}

if (! isset($VERIFYTEXTAREA)){
     $VERIFYTEXTAREA = "messagearea";
}

if (! isset($KEYSREADONLY)){
     $KEYSREADONLY = "yes";
}

if (! isset($KEYCREATION)){
     $KEYCREATION = "no";
}

if (! isset($DELETESECRETKEY)){
     $DELETESECRETKEY = "no";
}

if (! isset($FLEXIBLE)){
     $FLEXIBLE = "no";
}

if (! isset($ADDPRE)){
     $ADDPRE = "no";
}

if (! isset($FORYOUREYESONLY)){
     $FORYOUREYESONLY = "no";
}

if (! isset($REMOVEBR)){
     $REMOVEBR = "no";
}


/*
-----BEGIN PGP SIGNATURE-----
Version: GnuPG v1.4.5 (GNU/Linux)

iQIVAwUBU9mDxPv24sKOnJjdAQJ+Ag//U+sKA5V7jBFCuymkIEz9tw6NRrrmdqWe
WZNJSEoMMWe4NgpCs7uiwhsxPYHwVq2X8GhGEObGtLbhbtuZW7KDgVXB1aTslIn9
Bf90bu3EqluVO4nzwlRJ+tAFJk57cCKI6eMP0m8FUMl/ksQduNLam2d5yBE/IWr5
pq8oCW+ZzwpMT4wUM4JkEDojpO9yVD9d9aNHEjGO7VhAPXON5gUg7jkjDJmWI9JY
nhtvEb2/Js5FVDZo5QF6j3CMWGtlfWy5hMFAcOPHtz8AC1eaqBohYclie0YntiK7
0eZ6nyQGylR7ll6xq1FMdQ4f+YYMmx9FbTGfT+iwcTFhhVz26zevxk/0StxzN7q7
yPMQ8gM/BebOC3ydNbiSYp9qho1XDt1v/YqN+atmHNvNm/IizbSEhyxBwrQ+SuzV
br73L4vqoc+aJwu4jdrW+frxQMcStVIuC5XV4ggopFNvjtmm2ytt+wuHRO0khAoo
ODT+ctIAI2C5CLXzQ6F3+5Ygg/ZJkJnxI8Pkd9DxaCkjdMbPAcnuWq2v7QB+/TUT
7KlEH/HfmeNce+pFnwwCrGxgo7HimXonJE5xsNkhojNCmGX+CP7qbh3CiFnETPia
B9DHoZLFBCaB8aBQTBtfo/zQ4dDkHgIm5L8mCsMmj545/m0AaHL5+GwuruWF/Yjg
DWx/gJviG9k=
=LRJl
-----END PGP SIGNATURE-----
*/?>
