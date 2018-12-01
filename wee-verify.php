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
* File     : wee-verify.php
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

//  check that data has arrived here via HTTPS
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

if (! isset($VERIFYIFRAMENUMBER)){
          $VERIFYIFRAMENUMBER = 0;
}

if (isset($_REQUEST[$VERIFYTEXTAREA])) {
          $TEXT = $_REQUEST[$VERIFYTEXTAREA];
}

echo "<body onload='javascript:gettext(\"".$VERIFYINPUT."\");'>\n";
echo "<div class=verify>\n";

if (isset($TEXT) && (strlen($TEXT) > 20) )
{
          // perform verification
          echo "<h3>Signature Verification</h3>\n";
          $STATUSFILE = $GPGDIR."/status";
          unix ("rm ".$STATUSFILE);
          $VRFY = " /usr/bin/gpg   --homedir ".$GPGDIR." --require-secmem  --batch  --no-tty --yes --logger-file ".$STATUSFILE."  --verify" ;
          unixpipe($VRFY,$TEXT);
          $handle = fopen($STATUSFILE, "r");
          $RESULT = fread($handle,20000000);
          fclose($handle);
          $RESULT = unix("cat ".$STATUSFILE);
          // check if verification is successful
          $ERR1 = strpos($RESULT,'no signed data');
          $ERR2 = strpos($RESULT,'the signature could not be verified');
          if (($ERR1 === false) && ($ERR2 === false)){
               echo "<textarea name=result cols=80 rows=15>\n";
               echo htmlentities($RESULT);
               echo "\n</textarea>\n";
               echo "<p> <input type=button value='Use this message' onclick='javascript:update_inputfield(\"".$VERIFYINPUT."\");'>\n";
               echo "&nbsp;&nbsp;&nbsp;&nbsp;\n<input type=button value='Cancel' onclick='javascript:window.close();'>\n";
          }
          else {
               echo "<h3 class=error>Verification failed.</h3>";
               echo "<input type=button value='Cancel' onclick='javascript:window.close();'>\n";
          }
} else {
      // print form

      echo "<h3>Signature Verification</h3>\n";
      echo "<p><form name=verifyform method=POST action=wee-verify.php>\n";
      echo "\n<textarea class=text name=".$VERIFYTEXTAREA." cols=80 rows=15>\n";
      echo "\n</textarea>\n";
      echo "<p><input type=submit value='Verify this signed message'>";
      echo "&nbsp;&nbsp;&nbsp;&nbsp;\n";
      echo "<input type=submit value='Cancel' onclick='javascript:window.close();' >\n";
      echo "</form>\n";
}
echo "<p><center>version ".$VERSION." powered by <a href=https://impreza.host>Impreza Host</a></center><p>";
echo "</div>\n";
?>

<script type="text/javascript">

     function gettext(inputelement)
     {
          var text = "<?php echo $VERIFYTEXTAREA; ?>";
          var showtextarea = "<?php echo $SIGSHOWTEXTAREA;?>";
          var content = "";
          var success = false;
          var element = "none";
          var idelement = "none";
          if ("<?php echo $FLEXIBLE; ?>" == "yes") {
               try {
                    element = window.opener.document.getElementsByName('inputselector')[0].value;
               }
               catch (e) {
                    element = "<?php echo $VERIFYINPUTNAME; ?>";
               }
               try {
                    idelement = window.opener.document.getElementById('inputselector').value;
               }
               catch (e) {
                    idelement = "<?php echo $VERIFYINPUTID; ?>";
               }
          }
          else {
               element = "<?php echo $VERIFYINPUTNAME; ?>";
               idelement = "<?php echo $VERIFYINPUTID; ?>";
          }

          if (<?php echo strlen($TEXT);?> == "0") {
               if (inputelement == "editor" ) {
                    try {
                         if (showtextarea == "yes") {
                              content = window.opener.document.getElementsByName(text)[0].value;
                              window.document.getElementsByName(text)[0].value = content;
                         }
                         else {
                              content = window.opener.<?php echo $VERIFYINPUTNAME; ?>.getData();
                              window.document.getElementsByName(text)[0].value = content;
                         }
                    }
                    catch (e) {
                         window.document.write("The input element <?php echo $VERIFYINPUTNAME; ?> does not exist. Check the configuration.");
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
                         var fwin = window.opener.frames[<?php echo $VERIFYIFRAMENUMBER; ?>];
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


     function update_inputfield(inputelement)
     {
          var text = "<?php echo $VERIFYTEXTAREA; ?>";
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
                    element = "<?php echo $VERIFYINPUTNAME; ?>";
               }
               try {
                    idelement = window.opener.document.getElementById('inputselector').value;
               }
               catch (e) {
                    idelement = "<?php echo $VERIFYINPUTID; ?>";
               }
          }
          else {
               element = "<?php echo $VERIFYINPUTNAME; ?>";
               idelement = "<?php echo $VERIFYINPUTID; ?>";
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
                    window.opener.document.getElementsByName(element)[0].innerHTML = content;
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
                    var fwin = window.opener.frames[<?php echo $VERIFYIFRAMENUMBER; ?>];
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

iQIcBAEBAgAGBQJT0RJcAAoJEPv24sKOnJjdtCMQAKkXK5CsCe+g3LuFsxmob4wN
bTxDeBvrgLwPZzixkDRjjFidAdkYeb6ieXOata1/MoVVwZaGWsO+0gUyPE2VwbeE
zjR7Ah2ejQ7S1lFSe7ghSp3GELIYPpqTEAiDTGIsW8DxqALkYOi+5LcSY4CSwwXC
vdTiU+hk5RTE3dPTaH6osaUCYGngd/eD5Xyt7svzmdmEWRkYt6ZhgpufgnOYbkIg
IaWHR1NM7idMeToauB2lFqOVu0BcudFctsSsZkiWWLia2DTD86Hat1MTBM8qmorc
FqHRLJ/mBz6aW0vKd+7IGb4M6U8yX/n2X+TrMJoEhDJz7wHbRRG5dqYJ4VP9ql6O
0I8i9m6Ut5zABf6bM5hHa9yNjFbHIktxibmWtXhdo6Z59PYwv6EIBiQ/iVXSB9tE
AnqKfUzt2o308RYvi+SL03EQhhGd1w+s5IDR9wjOgxQk3gyM88J2VfRmoqRDeeQl
+pw09HjSu+VdFCnxlFg824R7WBmdaueC5LMR045+IZQ3ti55Oebtg95NPOROBYyx
VV4E/wvF5nbkoJvEybx0ZMINn34wzeEVk/LiBbPnh6HrxHWumTshLDs/n/8MGt7Y
rQ+Z3lRRXwTgzeoD9jzXn0tv1g1PuqneKb0hf1euD3bhx+oPRQPrcAUMl7byYPW1
rftAsdVhb3cDvDQbTlKx
=9xKB
-----END PGP SIGNATURE-----
-->
</body>
</html>
