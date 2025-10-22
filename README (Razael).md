- Download the requirements
    -   Need to have 3.9 python (it will show up a bunch of errors when tring to install the requirements when using an updated one), not the newest one. If you have the newest one you can download 3.9 aswell just put it in a separate folder.
    - In the installation page, check add python to PATH and check install for all users.
- Clone this github, preferably in the C: drive. (eg. C:\Real-time-IDS)
- Open the folder in VSCode and type "python --version" in the VScode terminal, make sure its 3.9.13
- Copy paste "venv\Scripts\activate" to create a virtual folder
    - If it is not python 3.9.13, press CTRL + SHIFT + P, and select Python: Select Intrepreter, then choose 
    .\venv\Scripts\python.exe
    - Another way is to go to venv\pyvenv.cfg and change the following to this:
        home = C:\Program Files\Python39 (Depends on where you put your python 3.9)
        include-system-site-packages = false
        version = 3.9.13
    - If this error pops up:
    venv\Scripts\activate : File C:\Real-time-IDS\venv\Scripts\Activate.ps1 cannot be loaded because running scripts is disabled on this system. For more information, see about_Execution_Policies at https:/go.microsoft.com/fwlink/?LinkID=135170. At line:1 char:1 + venv\Scripts\activate + ~~~~~~~~~~~~~~~~~~~~~ + CategoryInfo : SecurityError: (:) [], PSSecurityException + FullyQualifiedErrorId : UnauthorizedAccess
        Run Powershell as Administrator, and copy paste this:
        Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
    Or change the VScode terminal to cmd and copy paste this:
        venv\Scripts\activate.bat
- (venv) C:\Real-time-IDS>, If this is your command line then you are in the virtual environment already.
- Then install the requirements, copy paste this: "pip install -r requirements.txt"
    This part have a lot of errors for me, it depends on your installed modules, i suggest asking ChatGPT for help.
- Wait until installation finish then copy paste "python application.py"
- It should give u a link to a localhost.

Notes
- I changed the code from application.py (line 186 -217) because that block cause errors to pop up when running application.py. If you can access the link, clicking the detail text on the table will give errors. It has something to do with the explainer file in the models folder. since its a .dill file, idk how to change it. 



