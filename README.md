# Getstego-Steganography-system
Built a secure web application to hide and extract secret messages in image,audio and video files using LSB technique.Integrated AES encryption and key-based authentication for enhanced security.Developed using Python,OpenCV,Numpy and Stremlit with userfriendly interface.Achieved high accuracy while maintaining media quality.

**Abstract**

In an era where data privacy is paramount, concealing the existence of sensitive data is as 
critical as protecting its content. Steganography, the art of hiding messages in multimedia 
files, offers a robust solution for covert communication. This project, GetStego, presents a 
web-based, multi-format steganography system capable of embedding and extracting 
hidden messages within images, audio, and video files. It uses the Least Significant Bit (LSB) 
technique and a secure key-based mechanism to ensure that only intended recipients can 
decode the hidden data. The system is intuitive, cross-platform, and implemented entirely in 
Python, making it accessible and extensible.

**Execution**
Project Title: GetStego: An Intelligent Web-Based Multimedia Steganography System for Secure Communication 
Domain: Cyber Security and Information Security 
Objective: To develop a web-based system that allows users to securely hide and extract secret messages within multimedia files (images, audio, and video) using the Least Significant Bit (LSB) technique and key-based encryption. 
Technologies Used: 
_Component  _               _ Technology _
Programming Language         Python 
Web Framework                Streamlit 
Image Processing             Pillow (PIL)
Audio Handling               SoundFile 
Video Processing             OpenCV 
Encryption                   Key-based XOR Encryption 
Libraries                    NumPy, os, tempfile 

****Setup and Execution Steps ****
Follow these steps carefully       
**Step 1:** Install Python 
Make sure you have Python 3.8 or above installed. 
You can check using: 
python --version 
**Step 2:** Install Dependencies 
Navigate to your project folder in Command Prompt or Terminal: 
cd GetStego 
Then install all required libraries: 
pip install streamlit pillow opencv-python soundfile numpy 
**Step 3:** Run the Application 
Run the Streamlit app using: 
streamlit run app.py 
After a few seconds, it will open in your default browser at: 
http://localhost:8501 
**Step 4:** Using the System 
Embed (Hide Message): 
1. Select Mode → Embed (Hide Message) 
2. Select file type → Image / Audio / Video 
3. Enter a Secret Key (like mysecret123) 
4. Upload your carrier file (e.g., sample.png) 
5. Type your secret message 
6. Click      
Embed Message 
7. Download the generated stego file 
Extract (Reveal Message): use the above downloaded file. 
1. Select Mode → Extract (Reveal Message) 
2. Select the correct file type 
3. Enter the same Secret Key used during embedding 
4. Upload the stego file 
5. Click     
Extract Message 
6. The hidden message will appear on the screen 
OP for correct key 
OP for the wrong key 
Step 5: Supported File Formats 
Type Formats 
Image .png, .bmp 
Audio .wav 
Video .mp4, .avi 
Note: Do not use .jpg — it compresses data and can corrupt hidden information. 
Expected Output: 
• The stego file looks identical to the original. 
• When the correct key is used, the exact message is revealed. 
• With a wrong key, random or garbled text appears (for security). 
