<html>
<head>
   <link rel="stylesheet" type="text/css" href="gpgstyle.css" >
</head>
<body>
<?php

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
* File     : wee-keys.php
* Version  : 3.0
* License  : GPL-v3
* Signature: To protect the integrity of the source code, this program
*            is signed with the code signing key used by the copyright
*            holder, Ralf Senderek.
* Date     : Thursday 24 July 2014
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
*************************************************************/

//  check that data has arrived here via HTTPS
/* if ($_SERVER['HTTPS'] != "on") {
          die ("Use a secure HTTPS connection to the server. Aborting ...");
} */

// use GET only without data
if (strtoupper($_SERVER['REQUEST_METHOD']) != "POST") {
          //check if there is a query string, then abort.
          if (count($_GET) != 0){
                  die ("Always use POST to prevent recording of query strings. Aborting ...");
          }
}

if (! is_file("gpgconfig.php")){
          die ("Config file does not exist.");
}

require_once 'gpgconfig.php';

if (! is_dir($GPGDIR)){
          die ("GPG directory $GPGDIR does not exist.");
}
else {
          $ERRORFILE = $GPGDIR."/gpgerrors";
}

if (! isset($KEYEXPORT)) {
           $KEYEXPORT = "no";
}

if (! isset($SECRETKEYEXPORT)) {
           $SECRETKEYEXPORT = "no";
}

// FUNCTIONS

function listkeys (String $gpghome,String $type,String $select,String $export,String $secretexport) {
     unix ("/usr/bin/gpg --homedir ".$gpghome." --update-trustdb");
     if ($type == "secret") {
          echo "<h3>Secret Keys</h3>\n";
          $KEYS = unix2("/usr/bin/gpg --homedir ".$gpghome." --list-secret-keys --fingerprint",$gpghome);
     }
     else {
          echo "<h3>Public Keys</h3>\n";
          $KEYS = unix2("/usr/bin/gpg --homedir ".$gpghome." --list-keys --fingerprint", $gpghome);
     }

     $List = explode ("\n", $KEYS);
     if (count($List) < 2 ) {
          die ("<h3 class=error>No keys available. Aborting ...</h3>");
     }

     echo "<table class=keylist border=0 cellpadding=5>\n";
     $START = 0;
     foreach ($List as $Line){

          $START += 1;
          if (( substr_count($Line, "pub ") == 1) or(substr_count($Line, "sec ") == 1)){
               $START = 0;
               $PUB = $Line;
          }
          if ( $START == 1) {
               $FP = substr($Line,24);
          }
          if ( $START == 2) {
               $UID = htmlentities(substr($Line,4));
          }
          if ( $START == 3) {
               $SUB = $Line;
               echo "<tr><td class=keyid1>".$PUB."<br><i>(".$FP.")<br>".$SUB."</td>";
               if ($select) {
                    if ($type == "secret"){
                         echo " <td class=keyid2><input type=radio name=keyid value=\"".$FP."\"></td> ";
                    }
                    else {
                         echo " <td class=keyid2><input type=radio name=keyid value=\"".$UID."\"></td> ";
                    }
               }
               echo "<td class=keyid2>".$UID."</td>\n";
               if ($export == "yes") {
                    if (($type == "secret") && ($secretexport == "yes")) {
                         echo "<td class=keyid2><a href=wee-keys.php onclick='javascript:window.open(\"wee-export.php?keytype=secretkey&keyid=".trim($UID)."\",\"export\",\"\");' ><img src=export.png alt=export border=0></a></td>";
                    }
                    if ($type == "public")  {
                         echo "<td class=keyid2><a href=wee-keys.php onclick='javascript:window.open(\"wee-export.php?keytype=publickey&keyid=".trim($UID)."\",\"export\",\"\");' ><img src=export.png alt=export border=0></a></td>";
                    }
               }
               echo "</tr>\n";
          }
     }
     echo "</table>\n";
}


function addkeys (String $gpghome,String $key) {
     $FILENAME = $gpghome."/keyfile";
     $handle = fopen($FILENAME, "w");
     fwrite($handle,$key);
     fclose($handle);
     $CMD ="/usr/bin/gpg --homedir ".$gpghome." --import ".$FILENAME;
     $RESULT = unix($CMD);
     $ERR1 = strpos($RESULT,'No such file or directory');
     $ERR2 = strpos($RESULT,'no valid OpenPGP data found');
     if (! $ERR2 === false){
           echo "<h3 class=error>Please enter your key in ascii format.</h3>";
     }
     if (($ERR1 === false) && ($ERR2 === false) && (strlen($RESULT) > 0 )){
           // success
           echo "<p><textarea name=result cols=65 rows=5>";
           echo htmlentities($RESULT);
           echo "</textarea>\n";
           listkeys($gpghome,"public",false);
           listkeys($gpghome,"secret",false);
     }
     else {
           echo "<h3 class=error>Key import failed.</h3>";
     }
     unix("rm ".$FILENAME);
}


function removepubkey (String $gpghome,String $keyid) {

     $CMD ="/usr/bin/gpg --homedir ".$gpghome." --require-secmem --batch --no-tty --yes  --delete-key \"".trim($keyid)."\"";
     $RESULT = unix($CMD);
     $ERR1 = strpos($RESULT,'can\'t open');
     $ERR2 = strpos($RESULT,'not found:');
     $ERR3 = strpos($RESULT,'there is a secret key for public key');
     if (! $ERR1 === false){
           echo "<h3 class=error>Check file permissions on your keyring.</h3>";
     }
     if (! $ERR2 === false){
           echo "<h3 class=error>The key is not in your keyring.</h3>";
     }
     if (! $ERR3 === false){
           echo "<h3 class=error>You must remove the secret key first.</h3>";
     }
     if (($ERR1 === false) && ($ERR2 === false) && ($ERR3 === false)){
           // success
           if (strlen($RESULT) > 6 ) {
                echo "<p><textarea name=result cols=65 rows=5>";
                echo htmlentities($RESULT);
                echo "</textarea>\n";
           }
           listkeys($gpghome,"public",false,"","");
     }
     else {
           echo "<h3 class=error>Removing a key failed.</h3>";
     }
}

function removeseckey (String $gpghome,String $keyid) {

     $keyid = str_replace(" ","",$keyid);
     $CMD ="/usr/bin/gpg --homedir ".$gpghome." --require-secmem --batch --no-tty --yes  --delete-secret-key \"".trim($keyid)."\"";
     $RESULT = unix($CMD);
     $ERR1 = strpos($RESULT,'can\'t open');
     $ERR2 = strpos($RESULT,'not found:');
     if (! $ERR1 === false){
           echo "<h3 class=error>Check file permissions on your keyring.</h3>";
     }
     if (! $ERR2 === false){
           echo "<h3 class=error>The key is not in your keyring.</h3>";
     }
     if (($ERR1 === false) && ($ERR2 === false) ){
           // success
           if (strlen($RESULT) > 6 ) {
                echo "<p><textarea name=result cols=65 rows=5>";
                echo htmlentities($RESULT);
                echo "</textarea>\n";
           }
           listkeys($gpghome,"secret",false,"","");
     }
     else {
           echo "<h3 class=error>Removing a key failed.</h3>";
     }
}

function createkeys (String $gpghome,String $name,String $email,String $secret) {

     $name = htmlentities($name, ENT_QUOTES);
     $email = htmlentities($email, ENT_QUOTES);
     $secret = htmlentities($secret, ENT_QUOTES);

     $CMD ="/usr/bin/gpg --homedir ".$gpghome."  --gen-key --batch --logger-file ".$gpghome."/gpgerrors  << EOF\n";
     $CMD = $CMD."Key-Type: RSA\nKey-Length: 4096\nSubkey-Type: RSA\nSubkey-Length: 2048\nPassphrase: ".$secret."\nName-Real: ".$name."\nName-Email: ".$email."\nEOF\n";
	unix("find / > /dev/null &");
    $RESULT = unix($CMD);
    
    listkeys($gpghome, "secret", false,"","");
}


// MAIN
echo "<div class=keys>\n";
echo "<h2 class=title>Key Management for User $USERID</h2>\n";
if (! isset($_REQUEST['action'])) {
     echo "<form action=wee-keys.php method=POST>\n";
     echo "<select name=action>\n";
     echo "  <option value=listpublic>List public keys  </option>\n";
     echo "  <option value=listsecret>List secret keys  </option>\n";
     if ($KEYSREADONLY != "yes") {
          echo "  <option value=addkeys>Add keys </option>\n";
          echo "  <option value=removepkey>Remove a public key  </option>\n";
          echo "  <option value=removeskey>Remove a secret key  </option>\n";
          echo "  <option value=createkeys>Create a new key pair  </option>\n";
     }
     echo "</select>\n";
     echo "&nbsp;&nbsp;&nbsp;&nbsp;<input type=submit class=button value=\"Do it now\">\n";
     echo "</form>\n";
}
else {
     if ($_REQUEST['action'] == "listpublic") {
           listkeys($GPGDIR, "public",false, $KEYEXPORT, $SECRETKEYEXPORT);
           echo "<p><input type=button class=button value=\" Back \" onclick='javascript:window.history.back();'>\n";
     }

     if ($_REQUEST['action'] == "listsecret") {
           listkeys($GPGDIR, "secret",false, $KEYEXPORT, $SECRETKEYEXPORT);
           echo "<p><input type=button class=button value=\" Back \" onclick='javascript:window.history.back();'>\n";
     }

     if ($_REQUEST['action'] == "addkeys") {
           if (isset($_REQUEST['keyblock'])) {
                if ($KEYSREADONLY != "yes") {
                     addkeys($GPGDIR, $_REQUEST['keyblock']);
                }
           }
           else {
                // create form
                echo "<form method=POST action=wee-keys.php>\n";
                echo "<input type=hidden name=action value=addkeys>\n";
                echo "<h3>Adding New Keys</h3><p>";
                echo "<textarea name=keyblock cols=65 rows=15>\n";
                echo "Enter your keyblock here";
                echo "</textarea>\n";
                echo "<p><input type=submit class=button value=\"Add this key\">";
                echo "</form>\n";
           }
           echo "<p><input type=button class=button value=\" Back \" onclick='javascript:window.history.go(-2);'>\n";
     }

     if ($_REQUEST['action'] == "removepkey") {

           if (isset($_REQUEST['keyid'])) {
                if ($KEYSREADONLY != "yes") {
                     removepubkey($GPGDIR, checkinput($_REQUEST['keyid'],"noscript"));
                }
           }
           else {
                // create form
                echo "<form method=POST action=wee-keys.php>\n";
                echo "<input type=hidden name=action value=removepkey>\n";
                echo "<h3>Removing a Public Key</h3><p>";
                listkeys($GPGDIR,"public",true,"","");
                echo "<p><input type=submit class=button value=\"Remove this key\">";
                echo "</form>\n";
           }
           echo "<p><input type=button class=button value=\" Back \" onclick='javascript:window.history.go(-2);'>\n";
     }

     if ($_REQUEST['action'] == "removeskey") {

           if (isset($_REQUEST['keyid'])) {
                if (($KEYSREADONLY != "yes") && ($DELETESECRETKEY == "yes" )) {
                     removeseckey($GPGDIR, checkinput($_REQUEST['keyid'],"noscript"));
                }
                else {
                     echo "\n<h3 class=error>Deleting secret keys is not allowed.</h3>\n";
                }
           }
           else {
                // create form
                echo "<form method=POST action=wee-keys.php>\n";
                echo "<input type=hidden name=action value=removeskey>\n";
                echo "<h3>Removing a Secret Key</h3><p>";
                listkeys($GPGDIR,"secret",true,"","");
                echo "<p><input type=submit class=button value=\"Remove this key\">";
                echo "</form>\n";
           }
           echo "<p><input type=button class=button value=\" Back \" onclick='javascript:window.history.go(-2);'>\n";
     }

     if ($_REQUEST['action'] == "createkeys") {
           if (isset($_REQUEST['keyname']) and ($_REQUEST['keyemail']) and ($_REQUEST['keysecret'])) {
                if (($KEYSREADONLY != "yes") and ($KEYCREATION == "yes")) {
                     createkeys($GPGDIR, checkinput($_REQUEST['keyname'],"noscript") , checkinput($_REQUEST['keyemail'],"noscript") , checkinput($_REQUEST['keysecret'],"noscript"));
                }
                else {
                     echo "\n<h3 class=error>Key creation is not allowed.</h3>\n";
                }
           }
           else {
                // create form
                echo "<form method=POST action=wee-keys.php>\n";
                echo "<input type=hidden name=action value=createkeys>\n";
                echo "<h3>Creating A New Key Pair</h3><p>\n";
                echo "<p><table class=genkey>";
                echo "<tr><td class=label1>Key name</td><td class=label2> <input type=text name=keyname ></td></tr>\n";
                echo "<tr><td class=label1>Key email address</td><td class=label2> <input type=text name=keyemail ></td></tr>\n";
                echo "<tr><td class=label1>Secret passphrase</td><td class=label2> <input type=password name=keysecret ></td></tr>\n";
                echo "</table>\n";
                echo "<h4>This process may take some time. Please be patient.</h4>\n";
                echo "<p><input type=submit class=button value=\"Create key pair now\">\n";
                echo "</form>\n";
           }
           echo "<p><input type=button class=button value=\" Back \" onclick='javascript:window.history.go(-2);'>\n";
     }
}

echo "<p><center>version ".$VERSION." powered by <a href=https://impreza.host>Impreza Host</a></center><p>";
echo "</div>";

?>

<!--
-----BEGIN PGP SIGNATURE-----
Version: GnuPG v1.4.11 (GNU/Linux)

iQIcBAEBAgAGBQJT0gH8AAoJEPv24sKOnJjd/hcP/AgyXfiz2hbK112GCRgx2LlJ
zggMnJGXEe3bAnBpSqVCANEPeX9lZTUby6ff9a2rDkjH59HS4rBo8dNkAeAsPGWl
ChxYSTi/2935ovI3cBAtbAs4nSYcirIshUsTLLI8HsTTUxAfnbTegLhS9Op8OUa1
sJ35tqZgYfULQqM62a1DRXe0qqXOJIJJccK4FUgdwcQ3kVnB9VPUZzWQPUt36B2Q
mcr0SCY4GPERfrl7uk0Ap/2VVam8ep1SCaPnOVVTJ2Ao+blvA+Ly8Ug4OGlEAXkC
YVoYCoNWkr9W/ftbqvXM4LtXjLqKdA6L5UvlgavWFr6XhZmLU4cxyfwBs33yzOVu
T6Va2LQawF23q1yXCZvK7mQ9ynVFJV2iT5Q8mtHKpt4tQmt/q6ahMNRXzJIoOV6h
TaxOFwquL6u5I5Jk1r0J5F1BkQTPgvaKlLa2n6itodX+7FzT9jFUVLc7RqH6oKr9
LAO4Dxz+l6N1v6rnyXStpPZUS3wrW6WSX7Iw/NpU2rx5UxUM2mMSqWslrI0NT1DS
xGtdCj8WEaY/H0Fz8ZEmtaibsF2mKKXvxqznq/w2eou1JCjpsZnh8/lrIaBpzv7A
iqxUFKFIXe4bEbidZ3HFTH9J9KDzsDjrknBWHFqk3lWeY3jVb3dHcQCEpPUki19z
Oa8Ebixv95FbM74awr8h
=STgr
-----END PGP SIGNATURE-----
-->
</body>
</html>
