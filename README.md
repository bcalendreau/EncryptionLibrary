# EncryptionLibrary
A simple library to encrypt and decrypt sensitive data on Android using AES key. Support from API 18
 <hr>
 
 <ul>
 <li> Open your project in Android Studio </li>
 <li>Download the library</li>
  <li>Go to File > Import Module and import the library as a module</li>
  <li>Right-click your app in project view and select "Open Module Settings"</li>
  <li>Click the "Dependencies" tab and then the '+' button</li>
  <li>Select "Module Dependency"</li>
  <li>Select ":encryptionlibrary"</li>
 </ul>
 
<hr>

To use, you have the following public methods :

<strong>FOR ENCRYPTION</strong>

<ol>
  <li>Create a new <em>Encryptor(@Nullable context)</em> object. For API < 23 you must pass in a Context </li>
  <li>Then you use the <em>encryptText(String alias, byte[] textToEncrypt)</em> method which returns a String
  <li>DON'T FORGET  just after to call <em>getIV()</em> and store it along with the encrypted text, you'll need it for decryption
  <li>You can now store the crypted data
</ol>
  
<strong>FOR DECRYPTION</strong>

<ol>
  <li>Create a new <em>Decryptor(@Nullable context)</em> object. For API < 23 you must pass in a Context </li>
  <li>Then you use the <em>decryptText(String alias, String textToDecrypt, String IV)</em> method which returns a byte[]
</ol>

Please feel free to ask any questions !
