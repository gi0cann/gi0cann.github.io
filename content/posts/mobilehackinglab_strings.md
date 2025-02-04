+++
date = '2025-02-01T23:46:51-05:00'
tags = ["android", "mobile", "activities", "frida", "writeup", "intent", "intent filter"]
category = ["Mobile Hacking Lab Android Labs"]
draft = false
title = 'Mobile Hacking Lab Android Lab - Strings Writeup'
+++
Our objective for the Strings lab is to find the hidden flag by investigating the app component and by using dynamic instrumentation.

Running the provided application gives use the following:

![Strings main activity screenshot](/mhl_strings.png)

Looking at the AndroidManifest.xml file for the application we notice that in addition to the main activity the application has another exported activity `com.mobilehackinglab.challenge.Activity2`.

```xml
<activity
    android:name="com.mobilehackinglab.challenge.Activity2"
    android:exported="true">
    <intent-filter>
        <action android:name="android.intent.action.VIEW"/>
        <category android:name="android.intent.category.DEFAULT"/>
        <category android:name="android.intent.category.BROWSABLE"/>
        <data
            android:scheme="mhl"
            android:host="labs"/>
    </intent-filter>
</activity>
```
Looking at the intent filter for this activity we see that to launch it we need to use the scheme `mhl` and the host `labs`.

We attempt to launch is using the following command:
```shell
adb shell am start -a android.intent.action.VIEW -d "mhl://labs/" -n com.mobilehackinglab.challenge/.Activity2
```
Doing this closes tha application. Let take a closer look at `Activity2` to see what it's expecting from us to able to launch it.

```java
@Override // androidx.fragment.app.FragmentActivity, androidx.activity.ComponentActivity, androidx.core.app.ComponentActivity, android.app.Activity
protected void onCreate(Bundle savedInstanceState) {
    super.onCreate(savedInstanceState);
    setContentView(R.layout.activity_2);
    SharedPreferences sharedPreferences = getSharedPreferences("DAD4", 0);
    String u_1 = sharedPreferences.getString("UUU0133", null);
    boolean isActionView = Intrinsics.areEqual(getIntent().getAction(), "android.intent.action.VIEW");
    boolean isU1Matching = Intrinsics.areEqual(u_1, cd());
    if (isActionView && isU1Matching) {
        Uri uri = getIntent().getData();
        if (uri != null && Intrinsics.areEqual(uri.getScheme(), "mhl") && Intrinsics.areEqual(uri.getHost(), "labs")) {
            String base64Value = uri.getLastPathSegment();
            byte[] decodedValue = Base64.decode(base64Value, 0);
            if (decodedValue != null) {
                String ds = new String(decodedValue, Charsets.UTF_8);
                byte[] bytes = "your_secret_key_1234567890123456".getBytes(Charsets.UTF_8);
                Intrinsics.checkNotNullExpressionValue(bytes, "this as java.lang.String).getBytes(charset)");
                String str = decrypt("AES/CBC/PKCS5Padding", "bqGrDKdQ8zo26HflRsGvVA==", new SecretKeySpec(bytes, "AES"));
                if (str.equals(ds)) {
                    System.loadLibrary("flag");
                    String s = getflag();
                    Toast.makeText(getApplicationContext(), s, 1).show();
                    return;
                } else {
                    finishAffinity();
                    finish();
                    System.exit(0);
                    return;
                }
            }
            finishAffinity();
            finish();
            System.exit(0);
            return;
        }
        finishAffinity();
        finish();
        System.exit(0);
        return;
    }
    finishAffinity();
    finish();
    System.exit(0);
}
```

Looking at the code we can see that we need the following in order to launch `Activity2`:
- Set the `UUU0133` value in the `DAD4` shared preferences to the value of returned by the method `cd` which returns the current date in the `dd/MM/yyyy` format.
- Decrypt `bqGrDKdQ8zo26HflRsGvVA==` with the provided key `your_secret_key_1234567890123456`. 
- Base64 the decrypted value and use it as the last fragment of our data URI. `mhl://data/<decrypted base64 encrypted value here.>`
- Use the data URI to launch `Activity2`. This will execute the getflag native function that will store the flag in memory.
- Scan the application memory to dump flag.

## Creating the `DAD4` sharedPreferences.

Looking at MainActivity code we can that method KLOW does exactly what we need. 
```java
public final void KLOW() {
    SharedPreferences sharedPreferences = getSharedPreferences("DAD4", 0);
    SharedPreferences.Editor editor = sharedPreferences.edit();
    Intrinsics.checkNotNullExpressionValue(editor, "edit(...)");
    SimpleDateFormat sdf = new SimpleDateFormat("dd/MM/yyyy", Locale.getDefault());
    String cu_d = sdf.format(new Date());
    editor.putString("UUU0133", cu_d);
    editor.apply();
}
``` 
The problem is that this method is never called during normal execution. To get around this we will make use of frida to execute the KLOW method. The following frida script will take care of that.

```javascript
// KLOW.js
if (Java.available) {
    Java.perform(() => {
        Java.choose("com.mobilehackinglab.challenge.MainActivity", {
            onMatch: function(instance) {
                send(instance.KLOW());
            },
            onComplete: function() {
                send("done");
            }
        })
    })
} else {
    console.error("Java not available");
}
```
We save it to a file of our choosing and run the following command:
```shell
frida -U Strings -l KLOW.js
```
And with this we have created the `DAD4` shared preferences and set the `UUU0133` value to the current date.

## Getting the value for the last fragment.

Decrypt method:
```java
public final String decrypt(String algorithm, String cipherText, SecretKeySpec key) {
    Intrinsics.checkNotNullParameter(algorithm, "algorithm");
    Intrinsics.checkNotNullParameter(cipherText, "cipherText");
    Intrinsics.checkNotNullParameter(key, "key");
    Cipher cipher = Cipher.getInstance(algorithm);
    try {
        byte[] bytes = Activity2Kt.fixedIV.getBytes(Charsets.UTF_8);
        Intrinsics.checkNotNullExpressionValue(bytes, "this as java.lang.String).getBytes(charset)");
        IvParameterSpec ivSpec = new IvParameterSpec(bytes);
        cipher.init(2, key, ivSpec);
        byte[] decodedCipherText = Base64.decode(cipherText, 0);
        byte[] decrypted = cipher.doFinal(decodedCipherText);
        Intrinsics.checkNotNull(decrypted);
        return new String(decrypted, Charsets.UTF_8);
    } catch (Exception e) {
        throw new RuntimeException("Decryption failed", e);
    }
}
```

Getting our last fragment is simple enough. All we have to do is replacate the decrypt method and base64 encode the returned value. We do this using the following python script.

```python
## pip install pycryptodome
from Crypto.Cipher import AES
import base64
from Crypto.Util.Padding import unpad

def decrypt_aes_cbc_pkcs5(ciphertext, key, iv):
    """Decrypts AES-CBC encrypted data with PKCS5 padding."""

    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = cipher.decrypt(ciphertext)
    return unpad(plaintext, AES.block_size)

# Example usage
iv = b'1234567890123456' 
key = b'your_secret_key_1234567890123456' 
ciphertext_base64 = "bqGrDKdQ8zo26HflRsGvVA=="

ciphertext = base64.b64decode(ciphertext_base64)
decrypted_text = decrypt_aes_cbc_pkcs5(ciphertext, key, iv)

print(f"decrypted: {decrypted_text.decode('utf-8')}")
print(f"base64 encoded: {base64.b64encode(decrypted_text).decode('utf-8')}")
```
Running our script gives us the following output:
```shell
decrypted: mhl_secret_1337
base64 encoded: bWhsX3NlY3JldF8xMzM3
```
Now we can take the base64 encoded output and use in to build our intent:
```shell
adb shell am start -a android.intent.action.VIEW -d "mhl://labs/bWhsX3NlY3JldF8xMzM3" -n com.mobilehackinglab.challenge/.Activity2
```
With this command we are able to successfully launch `com.mobilehackinglab.challenge.Activity2`.

![Strings Activity2 success screenshot](/mhl_strings_activity2_success.png)

Now that we have successfully launched `Activity2` we can proceed to use frida to dump the flag from memory using the following script.
```javascript
// memoryScan.js
function stringToHex(str) {
  let hex = '';
  for (let i = 0; i < str.length; i++) {
    hex += str.charCodeAt(i).toString(16) + " ";
  }
  return hex.slice(0, -1);
}

const flagModule = Process.getModuleByName("libflag.so");
console.log(JSON.stringify(flagModule));

const pattern = stringToHex("MHL{");
console.log("patern: " + pattern);


Memory.scan(flagModule.base, flagModule.size, pattern, {
    onMatch(address, size) {
        console.log(address.readUtf8String());
        return 'stop';
    },
    onComplete() {
        console.log("Memory.scan() complete.");
    }
});
```
Output:
```shell
> frida frida -U Strings -l memoryScan.js 
     ____
    / _  |   Frida 16.6.4 - A world-class dynamic instrumentation toolkit
   | (_| |
    > _  |   Commands:
   /_/ |_|       help      -> Displays the help system
   . . . .       object?   -> Display information about 'object'
   . . . .       exit/quit -> Exit
   . . . .
   . . . .   More info at https://frida.re/docs/home/
   . . . .
   . . . .   Connected to Android Emulator 5554 (id=emulator-5554)
Attaching...                                                            
{"name":"libflag.so","base":"0x77ff7cb000","size":20480,"path":"/data/app/~~BkfNExZ2k0UV6MaIYQFPUQ==/com.mobilehackinglab.challenge-iejiH7VaOc4GYLrMXBcxxQ==/base.apk!/lib/arm64-v8a/libflag.so"}
patern: 4d 48 4c 7b
MHL{IN_THE_MEMORY}
Memory.scan() complete.
[Android Emulator 5554::Strings ]->
```
This gives us the flag: MHL{IN_THE_MEMORY}
