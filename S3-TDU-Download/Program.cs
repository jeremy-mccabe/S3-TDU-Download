using System;
using System.IO.Compression;
using System.IO;
using System.Security.Cryptography;
using System.Runtime.InteropServices;
using System.Threading.Tasks;
using Amazon.S3;
using Amazon.S3.Model;

/// REMINDER: Credentials are saved in the config file!
/// 
/// UPDATE ON NEW RUN:
/// 
/// -keyName: name used for AWS object creation on S3.
/// ie: Packaged-AWS-Object
/// 
/// -bucketName: name of the S3 bucket on AWS cloud.
/// ie: myAmazonUserName.testbucket1
/// 
/// -packagedData: name for compressed/encrypted file.
/// ie: Target-Dir.zip.aes
/// 
/// -decryptedResults: name for directory after it's been decrypted by AES
/// ie: Decrypted-Results.zip
/// 
/// -bucketRegion: specifies endpoint for AWS bucket.
/// RegionEndpoint.USEast1
/// 
/// -password: key used for AES encryption.
/// ie: p-a-s-s-w-o-r-d
/// 
/// -WriteAllBytes, FileDecrypt, File.Delete, encryption_path, zipPath, extractPath:
/// all need to be updated with the same string as workingDir (needs @ in front of string)
/// 
/// All "Old decryption functions" if using that algorithm.
/// 

namespace Amazon.Download
{
    class DownloadProgram
    {

        //  Call this function to remove the key from memory after use for security
        [DllImport("KERNEL32.DLL", EntryPoint = "RtlZeroMemory")]
        public static extern bool ZeroMemory(IntPtr Destination, int Length);

        // AWS PARAMETERS:
        // identifies bucket in AWS to access:
        private const string bucketName = "myAmazonUserName.testbucket1";
        // identifies object key in the bucket:
        private const string keyName = "Packaged-AWS-Object";
        // compressed/encrypted data file name:
        private const string packagedData = "Target-Dir.zip.aes";
        // names decrypted directory (resulting in .zip archieve):
        private const string decryptedResults = "Decrypted-Results.zip";
        // specify your bucket region (an example region is shown).
        private static readonly RegionEndpoint bucketRegion = RegionEndpoint.USEast1;
        // interface for accessing S3:
        private static IAmazonS3 client;

        public static byte[] ReadStream(Stream responseStream)
        {
            byte[] buffer = new byte[16 * 1024];
            using (MemoryStream ms = new MemoryStream())
            {
                int read;
                while ((read = responseStream.Read(buffer, 0, buffer.Length)) > 0)
                {
                    ms.Write(buffer, 0, read);
                }
                return ms.ToArray();
            }
        }

        // static AWS asynchronous download function:
        static async Task ReadObjectDataAsync()
        {
            // string responseBody = "";
            try
            {
                GetObjectRequest request = new GetObjectRequest
                {
                    BucketName = bucketName,
                    Key = keyName
                };
                using (GetObjectResponse response = await client.GetObjectAsync(request))
                using (Stream responseStream = response.ResponseStream)
                using (StreamReader reader = new StreamReader(responseStream))
                {
                    string title = response.Metadata["x-amz-meta-title"]; // Assume you have "title" as medata added to the object.
                    string contentType = response.Headers["Content-Type"];
                    Console.WriteLine("Object metadata, Title: {0}", title);
                    Console.WriteLine("Content type: {0}", contentType);

                    // byte array gathered from S3 response body to be processed by decrypt:
                    byte[] retrieved_encrypted = ReadStream(responseStream);

                    File.WriteAllBytes(@"C:\Users\jeremy\Desktop\TargetDir\" + packagedData, retrieved_encrypted);
                    // responseBody = reader.ReadToEnd();

                    // RIJNDAEL_DECRYPTION call:

                    string password = "p-a-s-s-w-o-r-d";
                    // For additional security Pin the password of your files
                    GCHandle gch = GCHandle.Alloc(password, GCHandleType.Pinned);
                    // Decrypt the file:
                    FileDecrypt(@"C:\Users\jeremy\Desktop\TargetDir\" + packagedData, @"C:\Users\jeremy\Desktop\TargetDir\" + decryptedResults, password);
                    // To increase the security of the decryption, delete the used password from the memory
                    ZeroMemory(gch.AddrOfPinnedObject(), password.Length * 2);
                    gch.Free();
                    // You can verify it by displaying its value later on the console (the password won't appear)
                    // Console.WriteLine("The given password is surely nothing: " + password);

                    File.Delete(@"C:\Users\jeremy\Desktop\TargetDir\" + packagedData);

                    // Old DECRYPTION - MSDN call:

                    // PARAMETERS:
                    /// resulting dir created from unzipping zipDir:
                    string resultsDir = "Final-Results";
                    /// file name after encryption (non-case sensitive):
                    string zippedAesFile = "Packaged-Data";
                    /// path name for dropping the unencrypted results:
                    string encryption_path = @"C:\Users\jeremy\Desktop\TargetDir\" + zippedAesFile;
                    /// file name for intermediary results before unarchiving:
                    string decryptedArchive = "Decrypted-Results.zip";

                    // Create a new instance of the Aes class.
                    // This generates a new key and initialization vector (IV).

                    using (Aes myAes = AesManaged.Create())
                    {

                        // DECOMPRESSION - MSDN
                        // try-catch block:
                        try
                        {

                            // decides on a destination for zipDir:
                            string zipPath = @"C:\Users\jeremy\Desktop\TargetDir\" + decryptedArchive;
                            Console.WriteLine("Zip path identified:\t\t\t\t" + zipPath);

                            // decides on where to drop the compressed results:
                            string extractPath = @"C:\Users\jeremy\Desktop\C#\" + resultsDir;
                            Console.WriteLine("Extract path identified:\t\t\t" + extractPath);

                            // creates new extracted dir from zipDir:
                            ZipFile.ExtractToDirectory(zipPath, extractPath, System.Text.Encoding.UTF8);
                            Console.WriteLine("Zip archive '" + resultsDir + "' successfully extracted.");

                            File.Delete(@"C:\Users\jeremy\Desktop\TargetDir\" + decryptedResults);


                        }
                        catch (System.IO.DirectoryNotFoundException e1)
                        {
                            string s = e1.Message;
                            Console.WriteLine("EXCEPTION THROWN: " + s);
                        }
                        catch (System.IO.IOException e2)
                        {
                            string s = e2.Message;
                            Console.WriteLine("EXCEPTION THROWN: " + s);
                        }
                    }
                }
            }
            catch (AmazonS3Exception e)
            {
                Console.WriteLine("Error encountered ***. Message:'{0}' when writing an object", e.Message);
            }
            catch (Exception e)
            {
                Console.WriteLine("Unknown encountered on server. Message:'{0}' when writing an object", e.Message);
            }
        }

        static void Main(string[] args)
        {

            // TRANSFER (Download) - AWS:
            client = new AmazonS3Client(bucketRegion);
            ReadObjectDataAsync().Wait();


        } // End Main function


        // RIJNDAEL_DECRYPTION:

        /// <summary>
        /// Decrypts an encrypted file with the FileEncrypt method through its path and the plain password.
        /// </summary>
        /// <param name="inputFile"></param>
        /// <param name="outputFile"></param>
        /// <param name="password"></param>
        /// 

        private static void FileDecrypt(string inputFile, string outputFile, string password)
        {
            byte[] passwordBytes = System.Text.Encoding.UTF8.GetBytes(password);
            byte[] salt = new byte[32];

            FileStream fsCrypt = new FileStream(inputFile, FileMode.Open);
            fsCrypt.Read(salt, 0, salt.Length);

            RijndaelManaged AES = new RijndaelManaged();
            AES.KeySize = 256;
            AES.BlockSize = 128;
            var key = new Rfc2898DeriveBytes(passwordBytes, salt, 50000);
            AES.Key = key.GetBytes(AES.KeySize / 8);
            AES.IV = key.GetBytes(AES.BlockSize / 8);
            AES.Padding = PaddingMode.PKCS7;
            AES.Mode = CipherMode.CFB;

            CryptoStream cs = new CryptoStream(fsCrypt, AES.CreateDecryptor(), CryptoStreamMode.Read);

            FileStream fsOut = new FileStream(outputFile, FileMode.Create);

            int read;
            byte[] buffer = new byte[1048576];

            try
            {
                while ((read = cs.Read(buffer, 0, buffer.Length)) > 0)
                {
                    // Application.DoEvents();
                    fsOut.Write(buffer, 0, read);
                }
            }
            catch (CryptographicException ex_CryptographicException)
            {
                Console.WriteLine("CryptographicException error: " + ex_CryptographicException.Message);
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error: " + ex.Message);
            }

            try
            {
                cs.Close();
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error by closing CryptoStream: " + ex.Message);
            }
            finally
            {
                fsOut.Close();
                fsCrypt.Close();
            }
        }


        // Old AES_DECRYPTION function:
        static string DecryptStringFromBytes_Aes(byte[] cipherText, byte[] Key, byte[] IV)
        {
            // Check arguments.
            if (cipherText == null || cipherText.Length <= 0)
                throw new ArgumentNullException("cipherText");
            if (Key == null || Key.Length <= 0)
                throw new ArgumentNullException("Key");
            if (IV == null || IV.Length <= 0)
                throw new ArgumentNullException("IV");


            // Declare the string used to hold
            // the decrypted text.
            string plaintext = "";

            // Create an Aes object
            // with the specified key and IV.
            using (Aes aesAlg = AesManaged.Create())
            {

                aesAlg.BlockSize = 128;
                aesAlg.KeySize = 128;
                aesAlg.Mode = CipherMode.CBC;
                aesAlg.Padding = PaddingMode.PKCS7;
                // Should set Key and IV here.  Good approach: 
                // derive them from a password via Cryptography.Rfc2898DeriveBytes 
                aesAlg.Key = Key;
                aesAlg.IV = IV;

                // Create a decryptor to perform the stream transform.
                ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);

                // Create the streams used for decryption.
                using (MemoryStream msDecrypt = new MemoryStream(cipherText))
                {
                    using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                    {
                        using (StreamReader srDecrypt = new StreamReader(csDecrypt))
                        {
                            // Read the decrypted bytes from the decrypting stream
                            // and place them in a string.
                            plaintext = srDecrypt.ReadToEnd();
                        }
                    }
                }
            }

            return plaintext;
        }

    } // End Program class

} // End S3-TDU-Upload namespace