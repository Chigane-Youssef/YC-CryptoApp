# -*- coding: utf-8 -*-
""" @author : CHIGANE Youssef""" 

from tkinter import *
from hashlib import sha1
import pickle
from tkinter import filedialog
import os
from tkinterdnd2 import *
from tkinter import messagebox

class Login:
    def __init__(self,master):
        master.title("Login-EncryptionApp")
        master.geometry("1000x500")
        master.maxsize(360,240)
        master.minsize(360,240)
        master.configure(background='pink')
        self.user = StringVar()
        self.password = StringVar()
        
        self.frame = Frame(master)
        self.user_label = Label(master,text="Username:",font=("Courrier",13,"bold"),fg="black",bg="silver",borderwidth=2, relief="groove").\
                    pack(fill=X,pady=10, padx=10)
        self.user_entry = Entry(master,textvariable=self.user,font=("times new roman",13),bg="white").\
                    pack(fill=X,pady=10, padx=10)
        self.password_label = Label(master,text="Password:",font=("Courrier",13,"bold"),fg="black",bg="silver",borderwidth=2, relief="groove").\
                    pack(fill=X,pady=10, padx=10)
        self.password_entry = Entry(master,textvariable=self.password,font=("times new roman",13),bg="white",show="*").\
                    pack(fill=X,pady=10, padx=10)
        self.log_button = Button(master,text="Login",fg="white",bg="#d77337",font=("times new roman",13),command=self.login).\
                    pack(side=BOTTOM,fill=X,pady=10, padx=10)
                    
    def login(self):
        if sha1(self.user.get().encode()).hexdigest()=='user_id crypted' and  sha1(self.password.get().encode()).hexdigest()=='user_pass crypted':
            for item in root.winfo_children():
                item.destroy()
            root.configure(background='gold')
            encrypt_button = Button(root,text="Encryption",fg="gold",bg="black",font=("times new roman",20,"bold"),command=self.encrypt).pack(fill=X,expand=True,pady=15, padx=10)
            decrypt_button = Button(root,text="Decryption",fg="gold",bg="black",font=("times new roman",20,"bold"),command=self.decrypt).pack(fill=X,expand=True,pady=15, padx=10)
        else : 
               messagebox.showinfo("Error","Login failed",parent=self.frame)
               
    def encrypt(self):
        for item in root.winfo_children():
                item.destroy()
                
        root.configure(background='pink')
        self.ide = StringVar()
        self.pas = StringVar()
        self.acc = StringVar()
        
        self.ide_label = Label(root,text="Identifiant:",font=("Courrier",13,"bold"),fg="black",bg="silver",borderwidth=2, relief="groove").\
                    pack(fill=X,pady=5, padx=10)
        self.ide_entry = Entry(root,textvariable=self.ide,font=("times new roman",10),bg="white").\
                    pack(fill=X,pady=5, padx=10)
        self.pas_label = Label(root,text="Mdp:",font=("Courrier",13,"bold"),fg="black",bg="silver",borderwidth=2, relief="groove").\
                    pack(fill=X,pady=5, padx=10)
        self.pas_entry = Entry(root,textvariable=self.pas,font=("times new roman",10),bg="white").\
                    pack(fill=X,pady=5, padx=10)
        self.acc_label = Label(root,text="TYPE@:",font=("Courrier",13,"bold"),fg="black",bg="silver",borderwidth=2, relief="groove").\
                    pack(fill=X,pady=5, padx=10)
        self.acc_entry = Entry(root,textvariable=self.acc,font=("times new roman",10),bg="white").\
                    pack(fill=X,pady=5, padx=10)
        self.log_button = Button(root,text="Save",fg="white",bg="blue",font=("times new roman",13,"bold"),command=self.saver).\
                    pack(side=BOTTOM,fill=X,pady=10, padx=10)
                    
    def decrypt(self):
        for item in root.winfo_children():
                item.destroy()

        self.label_id = Label(root,text="put _crypted file",font=("times new roman",10,"bold"),width=20,bg="gold").grid(row = 0, column = 0,sticky = W, pady = 2)
        self.label_pass = Label(root,text="put _key file",font=("times new roman",10,"bold"),width=20,bg="gold").grid(row = 0, column = 1,sticky = W, pady = 2,padx=10)
        self.frame_id = Frame(root,width=170,height=110)
        self.frame_id.grid(row = 1, column = 0, pady = 20,padx=5)
        self.frame_pass = Frame(root,width=170,height=110)
        self.frame_pass.grid(row = 1, column = 1, pady = 20,padx=5)
        self.new_decrypt = Button(root,text="Decrypt_New",fg="white",bg="black",font=("times new roman",13,"bold"),command=self.newer).grid(row = 2, column = 0, pady = 20)
        self.decrypt = Button(root,text="Decrypt",fg="white",bg="green",font=("times new roman",13,"bold"),command=self.decrypt_done).grid(row = 2, column = 1, pady = 20)

        self.frame_id.configure(background='gray')
        self.frame_pass.configure(background='gray')
        
        self.frame_id.drop_target_register(DND_FILES)
        self.frame_id.dnd_bind('<<Drop>>', self.verified1)
        
        self.frame_pass.drop_target_register(DND_FILES)
        self.frame_pass.dnd_bind('<<Drop>>', self.verified2)
        
        self.results_id=""
        self.results_pass=""
    
    def newer(self):
        self.frame_id.configure(background='gray')
        self.frame_pass.configure(background='gray')
        
        
    def verified1(self,event):
        self.frame_id.configure(background='green')
        with open(event.data,'rb') as f:
            data_id = pickle.Unpickler(f)
            self.results_id = data_id.load()

    def verified2(self,event):
        self.frame_pass.configure(background='green')
        with open(event.data,'rb') as f:
            data_id = pickle.Unpickler(f)
            self.results_pass = data_id.load()
            
    def decrypt_done(self):
        try:
            key1 = self.results_pass['aut_key']
            identifiant = self.results_id['aut_text']
            for i in range(len(identifiant)):
                pix = list(identifiant[i])
                for j in range(len(pix)):
                    if int(pix[j]) != int(key1[0]):
                        pix[j] = "1"
                    else:
                        pix[j] = "0"
                    key1 = key1[1:]
                identifiant[i] = pix
                
            key2 = self.results_pass['pass_key']
            mdp = self.results_id['pass_text']
            for i in range(len(mdp)):
                pix = list(mdp[i])
                for j in range(len(pix)):
                    if int(pix[j]) != int(key2[0]):
                        pix[j] = "1"
                    else:
                        pix[j] = "0"
                    key2 = key2[1:]
                mdp[i] = pix
                
            root2 = Tk()
            label_display1 = Label(root2,text="@ : "+"".join(chr(int("".join(e),2)) for e in identifiant)).pack()
            label_display2 = Label(root2,text="*** : "+"".join(chr(int("".join(e),2)) for e in mdp)).pack()
            root2.mainloop()
        except:
            messagebox.showinfo("Error","Error, verify the files before insering them",parent=root)
    
    def saver(self):
        path = filedialog.askdirectory (title = "Sélectionnez un répertoire de destination ...")
                
        texto_id = [format(ord(c), 'b') for c in self.ide.get()]
        texto_pass = [format(ord(c), 'b') for c in self.pas.get()]
        key_id = os.urandom(len(texto_id)*2).decode('latin1')
        key_pass = os.urandom(len(texto_pass)*2).decode('latin1')
        key_id = ''.join(format(ord(c), 'b') for c in key_id)
        key_pass = ''.join(format(ord(c), 'b') for c in key_pass)
        
        flag=True
        p=0
        while flag:
            try:
                p+=1
                f=open(path +"/"+self.acc.get()+"_key"+str(p))
                f.close()
            except:
                flag=False
                
        with open(path +"/"+self.acc.get()+"_key"+str(p),'wb') as f:
            fichier = pickle.Pickler(f)
            fichier.dump({'aut_key':key_id,'pass_key':key_pass})
            
        for i in range(len(texto_id)):
            pix = list(texto_id[i])
            for j in range(len(pix)):
                pix[j] = int(pix[j])^int(key_id[0])
                key_id = key_id[1:]
            texto_id[i] = pix

        for i in range(len(texto_pass)):
            pix = list(texto_pass[i])
            for j in range(len(pix)):
                pix[j] = int(pix[j])^int(key_pass[0])
                key_pass = key_pass[1:]
            texto_pass[i] = pix
            
        flag=True
        p=0
        while flag:
            try:
                p+=1
                f=open(path +"/"+self.acc.get()+"_crypted"+str(p))
                f.close()
            except:
                flag=False
            
        with open(path +"/"+self.acc.get()+"_crypted"+str(p),'wb') as f:
            fichier = pickle.Pickler(f)
            fichier.dump({'aut_text':texto_id,'pass_text':texto_pass})
        
        del(key_id)
        del(key_pass)
        del(texto_id)
        del(texto_pass)
        
root = Tk()
login = Login(root)
root.mainloop()
del(login)
del(root)