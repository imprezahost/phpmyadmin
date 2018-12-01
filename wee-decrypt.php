<html>
<head>
   <link rel="stylesheet" type="text/css" href="gpgstyle.css" >
</head>
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
* File     : wee-decrypt.php
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
*************************************************************/


//  check that data has arrived here via HTTPS
/* if ($_SERVER['HTTPS'] != "on") {
          die ("Use a secure HTTPS connection to the server. Aborting ...");
} */

if (! is_file("gpgconfig.php")){
          die ("Config file does not exist.");
}

require_once('gpgconfig.php');

if (! isset($DATADIR)){
          $DATADIR = "/none";
          $FILESDIR = "/none";
}

// use GET only when filename is given
if (strtoupper($_SERVER['REQUEST_METHOD']) != "POST") {
          //check if there is a query string, then abort except if files are to be handled.
          if (count($_GET) != 0){
                if ($INPUT != 'file') {
                      die ("Always use POST to prevent recording of query strings. Aborting ...");
                } else {
                      if (isset($_REQUEST['file'])) {
                            // touch legitimate files only !
                            if (isset($USERID)) {
                                  $FILESDIR = $DATADIR ."/". $USERID;
                            } else {
                                  $FILESDIR = $GPGDIR."/data";
                            }
                            $RELATIVEFILE = checkinput($_REQUEST['file'],"noscript");
                            $FILE = $FILESDIR ."/". $RELATIVEFILE;
                            $FILE = str_replace('//','/',$FILE);
                      } else {
                            $FILE = "/none";
                      }
                }
          }
} else {
          if (isset($_REQUEST['file'])) {
                // touch legitimate files only !
                if (isset($USERID)) {
                       $FILESDIR = $DATADIR ."/". $USERID;
                } else {
                       $FILESDIR = $GPGDIR."/data";
                }
                $RELATIVEFILE = checkinput($_REQUEST['file'],"noscript");
                $FILE = $FILESDIR ."/". $RELATIVEFILE;
                $FILE = str_replace('//','/',$FILE);
          }
}

if (! isset($RELATIVEFILE)){
          $RELATIVEFILE = "/none";
}

$FILE = str_replace('../','xxx',$FILE);

if (! is_dir($GPGDIR)){
          die ("GPG directory $GPGDIR does not exist.");
} else {
          $ERRORFILE = $GPGDIR."/gpgerrors";
}


if (! isset($DECRYPTBIGFILES)){
          $DECRYPTBIGFILES = "no";
}

if (! isset($PLAINRETURN)){
          $PLAINRETURN = "no";
}
$TEXT = "";
if (isset($_REQUEST[$DECRYPTIONTEXTAREA])) {
          $TEXT = $_REQUEST[$DECRYPTIONTEXTAREA];
          $TEXT = addslashes($TEXT);
}

if (isset($_REQUEST['secret'])) {
          $SECRET = checkinput($_REQUEST['secret'],"noscript");
}

if (! isset($KEYSELECTION)){
          $KEYSELECTION = "no";
}

if (! isset($DECRYPTIONIFRAMENUMBER)){
          $DECRYPTIONIFRAMENUMBER = 0;
}

if (! isset($REPLACEFILE)){
          $REPLACEFILE = "no";
}

if (isset($_REQUEST['decryptionkey'])){
          $DECRYPTIONKEY = checkinput($_REQUEST['decryptionkey'],"noscript");
}

echo "<body onload='javascript:gettext(\"".$DECRYPTIONINPUT."\");'>\n";
echo "<div class=decryption>\n";

if (isset($TEXT) && isset($SECRET))
{
          // perform decryption
          if (strlen($SECRET) > 0) {
               $ERRORFILE = $GPGDIR."/gpgerrors";
               unix("rm ".$ERRORFILE);
               echo "<h3>Decryption</h3>\n";

               // get random file name for plain text
               $rndhandle = fopen("/dev/urandom","r");
               $RND = fread($rndhandle,20);
               fclose($rndhandle);
               $FILENAME = $GPGDIR."/".sha1($RND);
               // $FILENAME will contain plain text data
               $CRYPTOGRAM = $GPGDIR."/".sha1($RND)."-encrypted.file";
               if ($DECRYPTBIGFILES == "yes"){
                    if ($INPUT == 'file') {
                         // decrypt a file
                         unix("touch ".$CRYPTOGRAM);
                         unix("chmod 600 ".$CRYPTOGRAM);
                         unix("cp \"".$FILE."\" ".$CRYPTOGRAM);
                         $SIZE = unix("wc -c ".$CRYPTOGRAM." | cut -f1 -d' ' ");
                         echo "<p>decrypting ".$SIZE." bytes ...<p>\n";
                         $ENC ="/usr/bin/gpg   --homedir ".$GPGDIR." --require-secmem  --batch  --no-tty --yes --logger-file ".$ERRORFILE." --passphrase ".$SECRET." --output ".$FILENAME." --decrypt ".$CRYPTOGRAM ;
                         unix($ENC);
                         unix("rm ".$CRYPTOGRAM);
                    } else {
                         $ENC ="/usr/bin/gpg   --homedir ".$GPGDIR." --require-secmem  --batch  --no-tty --yes --logger-file ".$ERRORFILE." --passphrase ".$SECRET." --output -  --decrypt > ".$FILENAME ;
                         unixpipe($ENC,$TEXT);
                    }
                    unix("chmod 600 ".$FILENAME);

                    $handle = fopen($FILENAME, "r");
                    $RESULT = fread($handle,20000000);
                    fclose($handle);

                    // $RESULT may contain code
                    $RESULT = checkinput($RESULT, "noscript");

                    if ($INPUT != 'file') {
                         // destroy content of the plain text file
                         unix("dd if=/dev/zero of=".$FILENAME." bs=1 count=".strlen($RESULT));
                         unix("sync");
                         unix("rm ".$FILENAME);
                    }
               } else {
                    $ENC ="echo \"".$TEXT."\" | /usr/bin/gpg   --homedir ".$GPGDIR." --require-secmem  --batch  --no-tty --yes --logger-file ".$ERRORFILE." --passphrase ".$SECRET." --output - --decrypt" ;
                    $RESULT = unix($ENC);
               }

               $ERRORS = unix("cat ".$ERRORFILE);
               echo "<textarea class=error cols=75 rows=4>".htmlentities($ERRORS)."</textarea>\n";
               // check if decryption is successful
               $ERR1 = strpos($RESULT,'No such file or directory');
               $ERR2 = strpos($RESULT,'no valid OpenPGP data found');
               if (($ERR1 === false) && ($ERR2 === false) && (strlen($RESULT) > 0 )){
                    echo "<p><h3>".strlen($RESULT)." bytes decrypted</h3>";
                    if ($INPUT != 'file') {
                         echo "<h3>Plain Text</h3>";
                         echo "\n<center><textarea name=result cols=75 rows=15>\n";
                         echo stripslashes($RESULT);
                         echo "\n</textarea></center>\n";
                         echo "<p> <input type=button value='Use this message' onclick='javascript:update_inputfield(\"".$DECRYPTIONINPUT."\");'>\n";
                         echo "&nbsp;&nbsp;&nbsp;&nbsp;\n<input type=button value='Cancel' onclick='javascript:window.close();'>\n";
                    } else {
                         if ($REPLACEFILE == "yes") {
                              unix("cp ".$FILENAME." \"".$FILE."\"");
                         } else {
                              // strip .asc from filename
                              if (substr($FILE,-4)  == '.asc') {
                                   $FNAME = substr($FILE,0,-4);
                              } else {
                                   $FNAME = $FILE;
                              }
                              unix("cp ".$FILENAME." \"".$FNAME."\"");
                         }
                         // destroy content of the plain text file
                         unix("dd if=/dev/zero of=".$FILENAME." bs=1 count=".strlen($RESULT));
                         unix("sync");
                         unix("rm ".$FILENAME);
                         echo "<input type=button value='Close' onclick='javascript:window.close();'>\n";
                    }
                    echo "<p><center>version ".$VERSION." powered by <a href=https://impreza.host>Impreza Host</a></center><p>";
               } else {
                    echo "<h3 class=error>Decryption failed.</h3>";
                    echo "<center><input type=button value='Close' onclick='javascript:window.close();'></center>\n";
               }
          } else {
               echo "<h3 class=error>Please enter a passphrase.</h3>";
               echo "<p><center><input type=button value='Close' onclick='javascript:window.close();'></center>\n";

          }
} else {
     // prompt for a passphrase
     echo "<h3>Decryption</h3>\n";
     echo "<h3>Available secret keys</h3>\n";
     $Keys = unix("/usr/bin/gpg --homedir $GPGDIR --list-secret-keys --fingerprint");
     $List = explode ("\n", $Keys);
     if (count($List) < 2 ) {
           die ("<h3 class=error>No keys available. Aborting ...</h3>");
     }

     echo "<table class=keylist border=0 cellpadding=5>\n";
     $START = 0;
     foreach ($List as $Line){

          $START += 1;
          if (substr_count($Line, "sec ") == 1) {
               $START = 0;
               $SEC = $Line;
          }
          if ( $START == 1) {
               $FP = substr($Line,24);
          }
          if ( $START == 2) {
               $UID = htmlentities(substr($Line,4));
          }
          if ( $START == 3) {
               $SUB = $Line;
               echo "<tr><td class=keyid1>".$SEC."<br>".$SUB."</td>";
               echo "<td class=keyid2>".$UID."</td>\n";
               echo "</tr>\n";
          }
     }
     echo "</table>\n";

     echo "<form name=decryptform method=POST action=wee-decrypt.php>\n";
     echo "<input type=hidden name=file value=\"".htmlentities($RELATIVEFILE)."\">\n";
     echo "<table class=keyselect border=0 cellpadding=5>\n";
     if (! isset($_REQUEST['secret'])) {
          echo "<tr><td class=input>Passphrase</td>";
          echo "<td class=input><input name=secret type=password size=25></td></tr>\n";
     } else {
          echo "<input name=secret type=hidden value=\"".$SECRET."\" >\n";
     }

     if ($INPUT != 'file') {
          echo "<tr><td colspan=2 class=text>\n<textarea class=text name=".$DECRYPTIONTEXTAREA." cols=75 rows=15>\n";
          if (isset($TEXT)){
               echo rawurlencode($TEXT);
          }
          echo "\n</textarea></td></tr>\n";
          echo "<tr><td colspan=2 class=input><center><input type=submit value='Decrypt this message'>";
          echo "&nbsp;&nbsp;&nbsp;&nbsp;\n";
          echo "<input type=submit value='Close' onclick='javascript:window.close();' ></center></td></tr>\n";
     } else {
          $FNAME = $FILE;
          if (isset($DATADIR)) {
               // strip directory name from filename
               $FNAME = substr($FNAME,strlen($DATADIR));
          }
          echo "<tr><td class=keyid2>File</td><td class=keyid2>".$FNAME."</td></tr>\n";
          echo "<tr><td colspan=2 class=input><center><input type=submit value='Decrypt file'>";
          echo "&nbsp;&nbsp;&nbsp;&nbsp;\n";
          echo "<input type=submit value='Close' onclick='javascript:window.close();' ></center></td></tr>\n";
     }
     echo "</table>\n";
     echo "</form>\n";
     echo "<p><center>powered by <a href=https://impreza.host>Impreza Host</a></center><p>";
}

echo "\n</div>\n";
?>

<script type="text/javascript">

     function gettext(inputelement)
     {
          var text = "<?php echo $DECRYPTIONTEXTAREA; ?>";
          var content = "";
          var success = false;
          var element = "none";
          var idelement = "none";
          if ("<?php echo $FLEXIBLE; ?>" == "yes") {
               try {
                    element = window.opener.document.getElementsByName('inputselector')[0].value;
               }
               catch (e) {
                    element = "<?php echo $DECRYPTIONINPUTNAME; ?>";
               }
               try {
                    idelement = window.opener.document.getElementById('inputselector').value;
               }
               catch (e) {
                    idelement = "<?php echo $DECRYPTIONINPUTID; ?>";
               }
          }
          else {
               element = "<?php echo $DECRYPTIONINPUTNAME; ?>";
               idelement = "<?php echo $DECRYPTIONINPUTID; ?>";
          }

          if (<?php echo strlen($TEXT);?> == "0") {
               if (inputelement == "editor") {
                    try {
                         content = window.opener.document.getElementsByName(text)[0].value;
                         window.document.getElementsByName(text)[0].value = content;
                    }
                    catch (e) {
                         window.close();
                    }
               }
               else if (inputelement == "textarea") {
                         try {
                              content = window.opener.document.getElementsByName(element)[0].value;
                              success = true;
                         } catch (e) {}
                         try {
                              content = window.opener.document.getElementById(idelement).value;
                              success = true;
                         } catch (e) {}
                         if (success) {
                              window.document.getElementsByName(text)[0].value = content;
                         }
                         else {
                              window.close();
                         }
               }
               else if (inputelement == "div") {
                         try {
                              content = window.opener.document.getElementsByName(element)[0].innerHTML;
                              success = true;
                         } catch (e) {}
                         try {
                              content = window.opener.document.getElementById(idelement).innerHTML;
                              success = true;
                         } catch (e) {}
                         if (success) {
                              window.document.getElementsByName(text)[0].value = content;
                         }
                         else {
                              window.close();
                         }
               }
               else if (inputelement == "iframe") {
                    try {
                         var fwin = window.opener.frames[<?php echo $DECRYPTIONIFRAMENUMBER; ?>];
                         content = fwin.document.getElementsByTagName('body')[0].innerHTML;
                         try {
                              if ("<?php echo $REMOVEBR; ?>" == "yes") {
                                   content = content.replace(/<br>/g,"");
                              }
                         } catch (e) {}
                         window.document.getElementsByName(text)[0].value = content;
                    } catch (e) {
                         window.document.write("The input element does not exist. Check the configuration.");
                    }
               }
          }
     }


     function update_inputfield(inputelement)
     {
          var text = "<?php echo $DECRYPTIONTEXTAREA; ?>";
          var plain = "<?php echo $PLAINRETURN; ?>";
          var content = window.document.getElementsByName("result")[0].value;
          if ("<?php echo $FORYOUREYESONLY; ?>" == "yes") {
               return false;
          }
          if ("<?php echo $ADDPRE; ?>" == "yes") {
               content = "\n<pre>\n" + content +  "\n</pre>\n";
          }

          var element = "none";
          var idelement = "none";
          if ("<?php echo $FLEXIBLE; ?>" == "yes") {
               try {
                    element = window.opener.document.getElementsByName('inputselector')[0].value;
               }
               catch (e) {
                    element = "<?php echo $DECRYPTIONINPUTNAME; ?>";
               }
               try {
                    idelement = window.opener.document.getElementById('inputselector').value;
               }
               catch (e) {
                    idelement = "<?php echo $DECRYPTIONINPUTID; ?>";
               }
          }
          else {
               element = "<?php echo $DECRYPTIONINPUTNAME; ?>";
               idelement = "<?php echo $DECRYPTIONINPUTID; ?>";
          }

          if (inputelement == "textarea") {
               try {
                    window.opener.document.getElementsByName(element)[0].value = content;
               } catch (e) {
                    window.opener.document.getElementById(idelement).value = content;
               }
          }
          else if (inputelement == "div") {
               try {
                    window.opener.document.getElementsByName(element)[0].value = content;
               } catch (e) {
                    window.opener.document.getElementById(idelement).innerHTML = content;
               }
          }
          else if (inputelement == "editor"){
               if (plain == "yes"){
                    window.opener.document.write(content);
               }
               else {
                    window.opener.document.getElementsByName(text)[0].value = content;
               }
          }
          else if (inputelement == "iframe"){
               var fwin = window.opener.frames[<?php echo $DECRYPTIONIFRAMENUMBER; ?>];
               fwin.document.getElementsByTagName('body')[0].innerHTML = content;

          }
          else{
               // nothing
          }
          window.close();
     }
</script>

<!--
-----BEGIN PGP SIGNATURE-----
Version: GnuPG v1.4.5 (GNU/Linux)

iQIVAwUBU9mKXvv24sKOnJjdAQJm2w/9GDdyuJDdaLre12t3NjaR4ytE6aUW0IKb
FdRf/zlUHdCTbhSOF9a3/TrfWMGE/I85oHoPtMdw1I3gFRCC+y2rokqD5JkGDWAC
+Joi3rEtT0862mTqo68Vk73vZy4GUki8/u+FreHfPMC5Uftqe76/YbRFADf7TPO9
gFXNuo4wEdHgNzNB10Co9uXjgdmVb2rLKhVXvyYvjb68SAMJu8YY7gktYb3QJyNq
bw6sajDO9bLv/KhcjgRcS7SRemEOfTO2P99NJTNkfpMo2XDWruKwJ0C81vwJCHeh
T63Ww74nrS6qs/One6KXLXwWr06wN1UkQi+mzaUzWXhBSi3OBg46fMfBptb1Gnoy
qMD1MqjocfFlKuu4suu6ule5UzTTJ3VytAevvor0Lw1GHkO8HOFlMtQVN99zE2J2
hVcNMOSKzzGmvpsYhoQxD/WpEgFnhTnwAh82in1s7VpA8AQp+MikvVJZaLdqBsjG
I6IbS16q3e8CfzIFiydgAIeLXbQIsxkG3pulRwzqcAPOJV4TBw3GaDKZjL6jtLMk
n2KphpYon3nbu3/3VZo96gkbap1WVBROeoC0zCF1ycw6MvNCLhfQYHai/C2YuCQz
Vf0OUPoxOk4Mr/+Sv9gWwxmdRlqLPn8bmfbU3gJScupggVv3pFgOSy5NcSkzcBHg
LevocD4YNCc=
=mFI4
-----END PGP SIGNATURE-----
-->
</body>
</html>
