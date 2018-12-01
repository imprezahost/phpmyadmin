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
* Copyright Ralf Senderek, Ireland 2012-2013. (http://senderek.ie)
*
* Update in 2018 by impreza.host (support@impreza.email)
*
* This file is part of the WEB ENCRYPTION EXTENSION (WEE)
* File     : wee-sign.php
* Version  : 3.0
* License  : GPL-v3
* Signature: To protect the integrity of the source code, this program
*            is signed with the code signing key used by the copyright
*            holder, Ralf Senderek.
* Date     : Thursday, 24 July 2014
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

// check that data has arrived here via HTTPS
/* if ($_SERVER['HTTPS'] != "on") {
          die ("Use a secure HTTPS connection to the server. Aborting ...");
} */

if (strtoupper($_SERVER['REQUEST_METHOD']) != "POST") {
          //check if there is a query string, then abort.
          if (count($_GET) != 0){
                die ("Always use POST to prevent recording of query strings. Aborting ...");
          }
}

if (! is_file("gpgconfig.php")){
          die ("Config file does not exist.");
}

require_once('gpgconfig.php');

if (! is_dir($GPGDIR)){
          die ("GPG directory $GPGDIR does not exist.");
}
else {
          $ERRORFILE = $GPGDIR."/gpgerrors";
}

if (! isset($SIGSHOWTEXTAREA)){
          $SIGSHOWTEXTAREA = "no";
}

if (isset($_REQUEST[$SIGTEXTAREA])) {
          $TEXT = $_REQUEST[$SIGTEXTAREA];
}

if (isset($_REQUEST['secret'])) {
          $SECRET = checkinput($_REQUEST['secret'],"noscript");
}

if (! isset($KEYSELECTION)){
          $KEYSELECTION = "no";
}

if (! isset($SIGIFRAMENUMBER)){
          $SIGIFRAMENUMBER = 0;
}

if (isset($_REQUEST['signingkey'])){
          $SIGNINGKEY = checkinput($_REQUEST['signingkey'],"noscript");
}
echo "<body onload='javascript:gettext(\"".$SIGINPUT."\");'>\n";
echo "<div class=signing>\n";

if (isset($SIGNINGKEY) && isset($TEXT) && isset($SECRET))
{
          // perform clear text signing
          if ((strlen($SECRET) > 0) && (strlen($SIGNINGKEY) > 0)) {
               $SIGNATURE = $GPGDIR."/signature";
               unix("rm ".$GPGDIR."/signature");

               echo "<h3>Signing with key:<br> \"".htmlentities($SIGNINGKEY)."\"</h3>\n";
               $SIG = "/usr/bin/gpg --homedir ".$GPGDIR." --require-secmem  --default-key \"".$SIGNINGKEY."\" --batch  --no-tty --yes --logger-file ".$ERRORFILE." --output ".$SIGNATURE." --passphrase ".$SECRET." --clearsign";
               unixpipe($SIG,$TEXT);
               $handle = fopen($SIGNATURE, "r");
               $RESULT = fread($handle,20000000);
               fclose($handle);
               // check if sgnature is successful
               $ERR = strpos($RESULT,'BEGIN PGP SIGNED MESSAGE');
               if (! $ERR === false) {
                    if ($SIGSHOWTEXTAREA == "yes"){
                         $RESULT = "&lt;textarea name=".$SIGTEXTAREA." cols=65 rows=20&gt;\n".$RESULT."\n&lt;/textarea&gt;\n";
                    }
                    echo "<center><textarea name=result cols=65 rows=15>\n\n";
                    echo $RESULT;
                    echo "\n</textarea></center>\n";
                    echo "<p> <input type=button value='Use this message' onclick='javascript:update_inputfield(\"".$SIGINPUT."\");'>\n";
                    echo "&nbsp;&nbsp;&nbsp;&nbsp;\n<input type=button value='Cancel' onclick='javascript:window.close();'>\n";
               }
               else {
                    echo "<h3 class=error>Signing failed.</h3>";
                    echo "<center><input type=button value='Cancel' onclick='javascript:window.close();'></center>\n";
               }
          }
          else {
               echo "<p><center><input type=button value='Close' onclick='javascript:window.close();'></center>\n";

          }

} else {
          // read a secret key from the keyring and get the message from the opening window
          if (! isset($SIGNINGKEY)) {
               if ($KEYSELECTION == "yes") {

                    echo "<h3>Signing A Message</h3>\n";
                    echo "<h3>Please choose one of the following secret keys</h3>\n";
                    $Keys = unix("home/gpg --homedir $GPGDIR --list-secret-keys");
                    $List = explode ("\n", $Keys);
                    if (count($List) < 2 ) {
                          die ("<h3 class=error>No keys available. Aborting ...</h3>");
                    }

                    echo "<div class=keylist><table class=keylist border=0 cellpadding=5>\n";
                    foreach ($List as $Line){
                         $KEYID = htmlentities(trim(substr($Line,4)));
                         if ( substr_count($Line, "sec ") == 1){
                               echo "<tr><td class=keyid1>".$KEYID."</td>";
                         }
                         if ( substr_count($Line, "uid ") == 1){
                              echo "<td class=keyid2><a href='javascript:selectkey(\"".$KEYID."\");'>".$KEYID."</a></td></tr>\n";
                         }
                    }
                    echo "</table></div><p>\n";

                    echo "<form name=signingform method=POST action=wee-sign.php>\n";
                    echo "<table class=keyselect border=0 cellpadding=5>\n";
                    echo "<tr><td class=input>Key</td><td class=input> <input name=signingkey type=text size=40></td></tr>\n";
                    if (! isset($_REQUEST['secret'])) {
                         echo "<tr><td class=input>Passphrase</td>";
                         echo "<td class=input><input name=secret type=password size=25></td></tr>\n";
                    }
                    else {
                         echo "<input name=secret type=hidden value=\"".$SECRET."\" >\n";
                    }
                    echo "<tr><td colspan=2 class=text>\n<textarea class=text name=".$SIGTEXTAREA." cols=65 rows=15>\n";
                    if (isset($TEXT)){
                         echo $TEXT;
                    }
                    echo "\n</textarea>\n</td></tr>\n";

                    echo "<tr><td colspan=2 class=input><center><input type=submit value='Sign this message'>";
                    echo "&nbsp;&nbsp;&nbsp;&nbsp;\n";
                    echo "<input type=submit value='Cancel' onclick='javascript:window.close();' ></center></td></tr>\n";
                    echo "</table>\n";
                    echo "</form>\n";
               } else {
                    echo "<h3 class=error>No signing key selected. Signing impossible.</h3>";
                    echo "<p><center><input type=submit value='cancel' onclick='javascript:window.close();' ></center>\n";
           }
      }
}
echo "<p><center>version ".$VERSION." powered by <a href=https://impreza.host>Impreza Host</a></center><p>";
echo "</div>\n";
?>

<script type="text/javascript">

 function gettext(inputelement)
 {
      var content = "";
      var success = false;
      var text = "<?php echo $SIGTEXTAREA; ?>";
      var element = "none";
      var idelement = "none";
      if ("<?php echo $FLEXIBLE; ?>" == "yes") {
           try {
                element = window.opener.document.getElementsByName('inputselector')[0].value;
           }
           catch (e) {
                element = "<?php echo $SIGINPUTNAME; ?>";
           }
           try {
                idelement = window.opener.document.getElementById('inputselector').value;
           }
           catch (e) {
                idelement = "<?php echo $SIGINPUTID; ?>";
           }
      }
      else {
           element = "<?php echo $SIGINPUTNAME; ?>";
           idelement = "<?php echo $SIGINPUTID; ?>";
      }

      if (<?php echo strlen($TEXT);?> == "0") {
               if (inputelement == "editor" ) {
                    try {
                         content = window.opener.<?php echo $SIGINPUTNAME; ?>.getData();
                         window.document.getElementsByName(text)[0].value = content;
                    }
                    catch (e) {
                         window.document.write("The input element <?php echo $SIGINPUTNAME; ?> does not exist. Check the configuration.");
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
                              window.document.write("The input element does not exist. Check the configuration.");
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
                              window.document.write("The input element does not exist. Check the configuration.");
                         }
               }
               else if (inputelement == "iframe") {
                    try {
                         var fwin = window.opener.frames[<?php echo $SIGIFRAMENUMBER; ?>];
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
               else {
                    window.document.write("Unknown input element. Please check the configuration.");
               }
          }
     }

     function selectkey(key)
     {
          window.document.getElementsByName("signingkey")[0].value = key;
     }


     function update_inputfield(inputelement)
     {
          var content = window.document.getElementsByName("result")[0].value;
          var element = "none";
          var idelement = "none";
          if ("<?php echo $ADDPRE; ?>" == "yes") {
               content = "\n<pre>\n" + content +  "\n</pre>\n";
          }

          if ("<?php echo $FLEXIBLE; ?>" == "yes") {
               try {
                    element = window.opener.document.getElementsByName('inputselector')[0].value;
               }
               catch (e) {
                    element = "<?php echo $SIGINPUTNAME; ?>";
               }
               try {
                    idelement = window.opener.document.getElementById('inputselector').value;
               }
               catch (e) {
                    idelement = "<?php echo $SIGINPUTID; ?>";
               }
          }
          else {
               element = "<?php echo $SIGINPUTNAME; ?>";
               idelement = "<?php echo $SIGINPUTID; ?>";
          }

          if (inputelement == "textarea" ) {
               try {
                    window.opener.document.getElementsByName(element)[0].value = content;
               } catch (e) {
                    window.opener.document.getElementById(idelement).value = content;
               }
          }
          else if (inputelement == "div" ) {
               try {
                    window.opener.document.getElementsByName(element)[0].innerHTML = content;
               } catch (e) {
                    window.opener.document.getElementById(idelement).innerHTML = content;
               }
          }
          else if (inputelement == "editor"){
               window.opener.<?php echo $SIGINPUTNAME; ?>.setData(content);
          }
          else if (inputelement == "iframe"){
               var fwin = window.opener.frames[<?php echo $SIGIFRAMENUMBER; ?>];
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
Version: GnuPG v1.4.11 (GNU/Linux)

iQIcBAEBAgAGBQJT0RIwAAoJEPv24sKOnJjdQDkP/0B0ZxgajcTM9t90CwkMRAS0
di6sKDgiXPV0HOiQFBATH+sOHfzVyNsC/wQaBdCAu9+yo+WjUx3SX6w515/EMOXV
RQWDBY84r9JoGRLe+0flFo9Fd2jvZ3lV6Qz0bk4sUGtSYtdLalUzHBYrxRUdtSFs
GmATozMiNlRRpB5WkgyoANuNYZ4WACGkEPF/qw1E0J0J76cISvHqvnkXFaiMopkj
t+LKUg1c6UJI9LZHxQKHUvoLhcFaJeJJw4bHhcPudDtw0oIxOof4ZGhukyKD79W1
MJpIHL1/hDhVZt77vEr64IfUQbRiLkbw45MGHL2LOgbEV84aMGPjyfwh038CUU/O
aCwGwA98HuIc6zJTfUDCWnWJRK2Tmq2Wi+yW8d6zLGr5TcYfd1uUv+jLoPbWiB/u
gWOzlL+OFmgA9FfV2xTyTZ4wFjkJOGbmCBhuec9DhKCozFO6llEcWSnASFO2LbZ0
IqjHCfdvh7H6i7cLsGOiNz9EpGWJ3EBtTQub+KdAon1PmHHsATxVutnR4CgJfu+p
ewzTGVsnpdnNNyXA6pbz/Wl58F8ACoIKfQvb7ZvflIMekKRXvUvCfEKIuZ/xdu+c
nj8quUUakR1WuwRqYy1M6ePPthP0o5VV4suPGWsz7ExNAUXvkaRDT5/WEIlQaBun
M4faFuZEzmvLdD/aBv7z
=Yohg
-----END PGP SIGNATURE-----
-->
</body>
</html>
