#!/usr/bin/env python3
#encoding: UTF-8
#
# Coded by @ajaxr3quest
#
from argparse import ArgumentParser
from datetime import datetime
import json
import os
import re
from scapy.all import *
import sys
import texttable
import time
import threading 
import random
import smtplib
import ssl

# GLOBALS

#carpetes
working_folder = os.path.dirname(os.path.realpath(__file__))
config_folder= os.path.join(working_folder,'config')
log_folder= os.path.join(working_folder,'logs')
export_folder= os.path.join(working_folder,'export')
import_folder= os.path.join(working_folder,'import')
database_folder=os.path.join(working_folder,'database')

#fitxers
config_file = os.path.join(config_folder,'config.json') 
smtp_config_file = os.path.join(config_folder,'smtp_config.json') 
log_file = os.path.join(log_folder,'log.txt')  
taula_arp_file =  os.path.join(database_folder,'arp.json')  
taula_alert_file = os.path.join(database_folder,'alert.json') 


#taules
taula_arp = []
taula_alert = []

#globals runtime
taula_arp_changed= False
save_arp_proc = ""
sniffer_running = False
sniffer_proc = ""
proccesing_packet_on = False
config_loaded = {}
smtp_config = {}
cua_alert = {}



def get_arguments():
    
    #parsejem els arguments de consola
    args_parser= ArgumentParser()
    args_parser.add_argument("-s","--sniff",dest="s_arg",help="start the program with the sniffer activated",action='store_true')
    args_parser.add_argument("-d","--disc",dest="d_arg",help="start the program launching an ARP discovery",action='store_true')
    args_parser.add_argument("--export",dest="export_arg",help="export ARP table to a CSV file")
    args_parser.add_argument("--import",dest="import_arg",help="import ARP table from a CSV file")

    arguments_consola = args_parser.parse_args()

    if arguments_consola.export_arg != None:
        export_arp_table(arguments_consola.export_arg.strip())
        time.sleep(1)
 
    if arguments_consola.import_arg != None:
        import_arp_table(arguments_consola.import_arg.strip()) 
        time.sleep(1)
    
    if arguments_consola.s_arg == True:
        start_sniff()

    if arguments_consola.d_arg == True:
        arp_discovery()
        

  


def check_program_tree():
    global config_folder, log_folder, export_folder, import_folder, database_folder
    
    folder_list= [config_folder, log_folder, export_folder, import_folder, database_folder]
    
    for folder in folder_list:
    
        if os.path.exists(folder) == False:
            os.makedirs(folder)
            print("[*] Folder "+folder+" has been created.")


#importem/creem el fitxer de config del programa
def load_config():
    
    global config_loaded
    #carreguem el fitxer de configuracio
    if os.path.exists(config_file):
        with open(config_file, 'r',encoding="utf-8") as f:
            config_loaded = json.load(f)
            clean_cmd()
            print_menu()
    
    #generem el fitxer de configuracio
    else:
        print_menu()
        yy = check_input("[?] Looks like your first time here. Do you want to create the config file? [y/y]: ", ["y"])
        
        if yy.lower() == "y":
            print("\r")
            sistema_operatiu = check_input("    Which OS are you using? [W=Windows/L=Linux]: ", ["W", "L"])
            ip_src = check_input_regex("    Enter your IP address: ", "ip")
            mac_src = check_input_regex("    Enter your MAC address [AA:BB:CC:DD:EE:FF]: ", "mac")
            net_sniff = check_input_regex("    Enter the target network range [example= 192.168.1.0/24]: ", "net")
            arp_disc_on = check_input("    Do you want to send ARP discoveries every hour? (stealthy fellow=n, I don't care if I'm being noticed=y) [y/n]: ", ["y", "n"])
            
            config_loaded = {"SO":sistema_operatiu, "IP_SRC":ip_src, "MAC_SRC":mac_src, "NET_SNIFF":net_sniff,"ARP_DISC_ON":arp_disc_on}
            
            with open(config_file, 'w',encoding="utf-8") as f:
                f.write(json.dumps(config_loaded))
                print("\r [*] The config file has been created. \r")






def check_input(input_text, input_opcions):
    inp = input(input_text).strip()
    while inp not in input_opcions:
        inp = input(input_text).strip()
        
    return inp


def add_to_log(log_text):
    global log_file
    
    log_text=datetime.now().strftime("%Y-%m-%d %H:%M:%S")+" -- "+log_text+"\n"
    
    if os.path.exists(log_file):
        with open(log_file,'a',encoding="utf-8") as f:
            f.write(log_text)
            
    else:
        with open(log_file,'w',encoding="utf-8") as f:
            f.write(log_text)
            
            
#afegim alertes a la cua
def add_to_cua_alert(alert_type,alert_msg):
    global cua_alert
    
    #afegim un br perque faci salt en el correu la linia
    alert_msg = alert_msg+"\n"
    
    #creem lelement o lafegim segons pertoqui
    if alert_type not in cua_alert:
        cua_alert[alert_type]= alert_msg
        
    else:
        cua_alert[alert_type]= cua_alert[alert_type]+alert_msg
    


def check_input_regex(input_text, input_regex):
    
    master_regex = {
        "ip":r'^([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})$',
        "net":r'^([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0]{1})\/[0-9]{2}$',
        "mac":r'^([0-9a-fA-F]{2}[\:]){5}[0-9a-fA-F]{2}$',
        "email":r'^[a-zA-Z0-9_-]{1,}[\@]{1}[a-zA-Z0-9_-]{1,}[\.][a-zA-Z0-9]{1,3}$',
        "number":r'^[0-9]{1,}$',
        "smtp_server":r'(^([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})$)|(^([a-zA-Z0-9]{1,}[\.]{1}){2}[a-zA-Z]{1,5}$)'
    }
    
    inp = input(input_text).strip()
    while re.search(master_regex[input_regex], inp) == None:
        inp = input(input_text).strip()
    
    return inp

#importem les alerts
def load_alerts():
    global taula_alert
    
    if os.path.exists(taula_alert_file):
        with open(taula_alert_file, 'r',encoding="utf-8") as f:
            taula_alert = json.load(f)

#guardem a la taula alerts
def save_alerts():
    with open(taula_alert_file, 'w',encoding="utf-8") as f:
        global taula_alert
        f.write(json.dumps(taula_alert))


#importem la taula ARP
def load_arp():
    if os.path.exists(taula_arp_file):
        with open(taula_arp_file, 'r',encoding="utf-8") as f:
            global taula_arp
            taula_arp = json.load(f)
    
    
#guardem a la taula ARP
def save_arp():
    global taula_arp_changed
    taula_arp_changed= False
    
    with open(taula_arp_file, 'w',encoding="utf-8") as f:
        global taula_arp
        f.write(json.dumps(taula_arp))
        
    
#planificar el seguent ARP
def table_arp_has_changed():
    global taula_arp_changed
    
    if taula_arp_changed == False:
        taula_arp_changed= True
        
        #planifiquem guardar la informacio al fitxer per daqui a un minut

        #recridem el proces cada minut
        save_arp_proc= threading.Timer(interval=30,function=save_arp)
        save_arp_proc.daemon = True
        save_arp_proc.start()
        
        
def export_arp_table(export_filename):
    global taula_arp, export_folder, sniffer_running
    
    export_file = os.path.join(export_folder,export_filename+'.csv')
    with open(export_file, 'w',encoding="utf-8") as f:
        
        reopen_sniff= False
        
        #parem lsnifer per no sobreescriure les dades
        if sniffer_running == True:
            stop_sniff('N')
            reopen_sniff= True
        
        
        export_lines= "id;hostname;ip;mac;first_seen;last_seen;spoof;hidden\n"
        for reg_arp in taula_arp:
            export_lines += str(reg_arp['id'])+";"+str(reg_arp['hostname'])+";"+ str(reg_arp['ip'])+";"+ str(reg_arp['mac'])+";"+str(reg_arp['first_seen'])+";"+str(reg_arp['last_seen'])+";"+str(reg_arp['spoof'])+";"+str(reg_arp['hidden'])+"\n"
        
        f.write(export_lines)
        print("[*] The export file has been created: "+export_file)
        
        #reobrim lsnifer si pertoca
        if reopen_sniff == True:
            start_sniff('N')
        
        
def import_arp_table(import_filename):
    global taula_arp, import_folder, sniffer_running
    
    import_file = os.path.join(import_folder,import_filename+'.csv')
    if os.path.exists(import_file):
         
        with open(import_file,encoding="utf-8") as f:
            
            linies= f.readlines()
            
            #comprovem que poguem parsejar correctament el fitxer
            if len(linies) <= 1:
                print("[!] The content of the file couldn't be parsed. There must be a header and one registry at least.")
                return False
            
            #comprovem la capcelera
            capcelera = parse_csv_line(linies.pop(0))
            capcelera_num_fields = 8
            capcelera_found_fields = 0
            
            for camp in capcelera:
                if camp in ['id','hostname','ip','mac','first_seen','last_seen', 'spoof','hidden']:
                    capcelera_found_fields += 1
                    
            if capcelera_num_fields != capcelera_found_fields:
                print("[!] The file doesn't have all required fields. Export the content of the ARP table to have a template to work with.")
                return False
            
            import_arp= []
            
            for linia in linies:
                line_values = parse_csv_line (linia)
                
                arp_line = {}
                
                i=0
                for camp in capcelera:
                    arp_line[camp] = line_values[i]
                    i += 1
                    
                #comprova que la data tingui el format correcte
                regex_data= r"^2[0-9]{3}[-]{1}[0-1]{1}[0-9]{1}[-]{1}[0-3]{1}[0-9]{1}[ ]{1}[0-2]{1}[0-9]{1}[\:]{1}[0-6]{1}[0-9]{1}[\:]{1}[0-6]{1}[0-9]{1}$"
                if bool(re.search(regex_data, arp_line["first_seen"])) == False or bool(re.search(regex_data, arp_line["last_seen"])) == False:
                    print ("[!] Incorrect date format detected. It must have the following format (yyyy-mm-dd hh:mm:ss)  2000-12-30 04:05:06 ")
                    return False
                
                import_arp.append(arp_line)
                
                
            if len(import_arp) > 0:
                
                reopen_sniff= False
        
                #parem lsnifer per no sobreescriure les dades
                if sniffer_running == True:
                    stop_sniff('N')
                    reopen_sniff= True
                
                taula_arp = import_arp
                table_arp_has_changed()
                print("[*] The file "+import_file+" has been imported. ")
                
                #reobrim lsnifer si pertoca
                if reopen_sniff == True:
                    start_sniff('N')
    
    else:
        print("[!] The file you are trying to import "+import_file+" doesn't exist.")
        return False
   
   
#pasa de string a array una linia de csv
def parse_csv_line(str_csv):
    
    str_csv = str_csv.strip()
    r = []
    csv_fields = str_csv.split(";")
    
    for csv_field in csv_fields:
        r.append(csv_field.strip())
        
    return r


# ------------------------------------------------------------------------------------------
# SNIFF ------------------------------------------------------------------------------------
# ------------------------------------------------------------------------------------------
 
    
def get_registry_by(fieldname,value):
    global taula_arp 

    r=[]
    #iterem per cada registre
    for reg_arp in taula_arp:
        if str(reg_arp[fieldname]) == str(value):
            r.append(reg_arp)
      
    if len(r) > 0:
        return r
    else:
        return False

def change_registry_by_id(arp_id, arp_values):

    global taula_arp 

    #iterem per cada registre i busquem el que sha de modificar
    for reg_arp in taula_arp:
        
        if str(reg_arp['id']) == str(arp_id):
            reg_arp[arp_values[0]] = arp_values[1]
                
                
    #fem un schedule per actualitzar el fitxer arp.json si el valor canviat no ha sigut el last_seen
    if arp_values[0] != "last_seen":
        table_arp_has_changed()
        
        #ensenya missatge segons correspongui
        if arp_values[0] == "hidden" and arp_values[1] == "Y":
            msg= "Registry with ID = " +str(arp_id) +" has been deleted. "
            print("[*] "+msg)
            add_to_log(msg)
            
        else:
            msg="Registry with ID = " +str(arp_id) +" has been updated. "
            print("[*] "+msg)
            add_to_log(msg)
         
        
def get_update_arp_params(comanda):
    
    #separem els parametres passats
    set_param = ""
    where_param = ""
    
    #separem la comanda en diferents grups
    comanda_split= re.split(r'^(u|update)([ ]{1,})(\-set|\-where)([ ]{1,})([a-zA-Z ]{1,})([=]{1})(.*)(\-set|\-where)([ ]{1,})([a-zA-Z ]{1,})([=]{1})(.*)$',comanda.strip())
    
    #procesem els parametres
    if len(comanda_split) == 14:
        
        #primer grup de parametres
        param1= comanda_split[3].strip()
        camp_param1= comanda_split[5].strip()
        valor_param1= comanda_split[7].strip()
        
        #segon grup de parametres
        param2= comanda_split[8].strip()
        camp_param2= comanda_split[10].strip()
        valor_param2= comanda_split[12].strip()
        
        camps_valids= ["hostname","ip","mac","id","spoof"]
        
        if camp_param1 in camps_valids and camp_param2 in camps_valids:
        
            if param1 == "-set" and param2 == '-where':
                set_param=[camp_param1,valor_param1]
                where_param=[camp_param2,valor_param2]
 

            elif param1 == "-where" and param2 == '-set':
                where_param=[camp_param1,valor_param1]
                set_param=[camp_param2,valor_param2]

            else:
                print("[!] Syntax error. Syntax: update/u -set <field> = X -where <field> = X ")
                return [False,False]
            
            return [set_param,where_param]
            
        else:
            print("[!] Wrong field used. Valid fields: id, hostname, ip, mac or spoof. ")
            return [False,False]
    
    else:
        print("[!] Syntax error. Syntax: update/u -set <field> = X -where <field> = X ")
        return [False,False]
        
    

def get_delete_arp_params(comanda):
    
    #separem la comanda en diferents grups
    comanda_split= re.split(r'^(del|delete)([ ]{1,})(\-where)([ ]{1,})([a-zA-Z ]{1,})([=]{1})(.*)$',comanda.strip())
    
    #procesem els parametres
    if len(comanda_split) == 9:
        
        #parametres
        where_str= comanda_split[3].strip()
        camp_where= comanda_split[5].strip()
        valor_where= comanda_split[7].strip()
        
        camps_valids= ["hostname","ip","mac","id","spoof"]
        
        if camp_where in camps_valids and where_str == "-where":
            if where_str == "-where":
                return [camp_where,valor_where]
                
            else:
                print("[!] Syntax error. Syntax: delete/del -where <field> = X ")
                return False

        else:
            print("[!] Wrong field used. Valid fields: id, hostname, ip, mac or spoof. ")
            return False
    
    else:
        print("[!] Syntax error. Syntax: delete/del -where <field> = X ")
        return False
      


def get_create_alert_params(comanda):
    
    #separem la comanda en diferents grups
    comanda_split= re.split(r'^(an|alertn)([ ]{1,})(\-to|\-when)([ ]{1,})(.*)(\-to|\-when)([ ]{1,})(.*)$',comanda.strip())
    
    to_param = []
    when_param = ""
    wrong_email= False
    
    #procesem els parametres
    if len(comanda_split) == 10:
        
        #primer grup de parametres
        param1= comanda_split[3].strip()
        valor_param1= comanda_split[5].strip()
        
        #segon grup de parametres
        param2= comanda_split[6].strip()
        valor_param2= comanda_split[8].strip()
        
        valid_when= ["new_host","spoof"]
        valid_param = ["-to","-when"]
        
        #mirem que els parametres siguin valids
        if param1 in valid_param and param2 in valid_param :
            
            temp_when= ""
            temp_to = []
            
            #parsejem els parametres segons vinguin ordenats
            if param1 == "-when" and param2 == '-to':
                temp_when = valor_param1
                temp_to = valor_param2
                
            elif param1 == '-to' and param2 == "-when":
                temp_to = valor_param1
                temp_when = valor_param2
                
            if temp_when in valid_when:
                when_param = temp_when

            #agafem qualsevol numero de correus entrats
            if len(temp_to)>0:
                for correu in temp_to.split(" "):
                    if re.search(r'^[a-zA-Z0-9_-]{1,}[\@]{1}[a-zA-Z0-9_-]{1,}[\.][a-zA-Z0-9]{1,3}$', correu) != None:
                        to_param.append(correu)
                    else:
                        wrong_email= True
                        print("[!] Wrong email: "+correu)
                
    
    #retornem segons els resultats
    if len(to_param) == 0 or when_param == "":
        print("[!] Syntax error. Syntax: alertn/an -to <value> -when <event>. Possible events: new_host, spoof ")
        return [False,False]
    else:
        if wrong_email == True:
            print("[!] The creation of the alert was aborted.")
            return [False,False]
        else:    
            return [to_param,when_param]
        
def get_delete_alert_id(comanda):
    
    #separem la comanda en diferents grups
    comanda_split= re.split(r'^(alertdel|adel)([ ]{1,})(\-where)([ ]{1,})([a-zA-Z ]{1,})([=]{1})(.*)$',comanda.strip())
    
    #procesem els parametres
    if len(comanda_split) == 9:
        
        #parametres
        where_str= comanda_split[3].strip()
        camp_where= comanda_split[5].strip()
        valor_where= comanda_split[7].strip()
        
        if camp_where == "id" and where_str == "-where":
            if where_str == "-where":
                return valor_where
     
    print("[!] Syntax error. Syntax: alertdel/adel -where id = X. It could only by identified by ID. ")
    return False
      


def get_table_params(comanda):
    
    table_action= False
    where_param = False
    
    #no te parametres adicionals
    if comanda in ['table','tables','table*','table?','tablea']:
        table_action= comanda.replace('table','')
        
    elif comanda in ['t','ts','t*','t?','ta']:
        table_action= comanda.replace('t','')
        
    #te parametres adicionals
    else:
        
        #separem els parametres passats
        params= re.split(r'^(t|table)(\*[ ]{1,}|\?[ ]{1,}|s[ ]{1,}||a[ ]{1,}|[ ]{1,})(\-where)([ ]{1,})([a-zA-Z ]{1,})([=]{1})(.*)$',comanda)

        #si tenim la quantitat que toca de parametres
        if len(params) == 9:
            
            #comprovem que el nom del camp sigui correcte
            camps_valids= ["hostname","ip","mac","id","spoof"]
            if params[5].strip() in camps_valids:
                where_param = [params[5].strip(),params[7].strip()]
                table_action = params[2].strip()

            
    return [table_action,where_param]

        
def show_table_arp(filter_by,filter_where):
    global taula_arp
    
    print("\r\r")
    
    #preparem els registres per la taula
    taula_arp_format = [["ID", "Hostname", "IP", "MAC", "First seen","Last seen"]]
    
    ara = datetime.now()
    

    #agafem els registres a mostrar
    for reg_arp in taula_arp:
        
        filter_where_cond= reg_arp["hidden"] =="N" and (filter_where == False or (filter_where != False and filter_where[1].lower() in reg_arp[filter_where[0]].lower() ) )
        
        abans=""
        if filter_by == "a":
            abans = datetime.strptime(reg_arp["last_seen"],"%Y-%m-%d %H:%M:%S")
        
        #filtre de editats (*)
        if filter_by == "*" and reg_arp["hostname"] != "" and filter_where_cond:
            taula_arp_format.append([reg_arp["id"], reg_arp["hostname"], reg_arp["ip"], reg_arp["mac"],  reg_arp["first_seen"], reg_arp["last_seen"]])

        #filtre de desconeguts (?)
        elif filter_by == "?" and reg_arp["hostname"] == "" and filter_where_cond:
            taula_arp_format.append([reg_arp["id"], reg_arp["hostname"], reg_arp["ip"], reg_arp["mac"],  reg_arp["first_seen"], reg_arp["last_seen"]])

        #filtre de taula spoof (s)
        elif filter_by == "s" and reg_arp["spoof"] == "Y" and filter_where_cond:
            taula_arp_format.append([reg_arp["id"], reg_arp["hostname"], reg_arp["ip"], reg_arp["mac"],  reg_arp["first_seen"], reg_arp["last_seen"]])

        #sense filtre
        elif filter_by == "" and filter_where_cond:
            taula_arp_format.append([reg_arp["id"], reg_arp["hostname"], reg_arp["ip"], reg_arp["mac"],  reg_arp["first_seen"], reg_arp["last_seen"]])
            
        elif filter_by == "a" and (ara - abans).seconds <= 180 and filter_where_cond:
            taula_arp_format.append([reg_arp["id"], reg_arp["hostname"], reg_arp["ip"], reg_arp["mac"],  reg_arp["first_seen"], reg_arp["last_seen"]])

    
    #pintem la taula
    if len(taula_arp_format)>1:
        
        taula = texttable.Texttable()
        taula.set_cols_align(["l", "l", "c", "c", "c","c"]) # align de les columnes
        taula.add_rows(taula_arp_format)
        print(taula.draw())
        
    else:
        print("[?] Empty ARP table or filtered view does not contain any match. ")
    
    
#procesem els paquets
def process_packet(paq):
    global sniffer_running, taula_arp, proccesing_packet_on
    
    if paq[ARP].psrc != "0.0.0.0" and paq[ARP].hwsrc != "00:00:00:00:00:00" and sniffer_running == True:
        spoof = "N"
        proccesing_packet_on = True
        #busquem el host per MAC
        arp_registries= get_registry_by("mac",paq[ARP].hwsrc)

        #si no lhem trobat, comprovem que no i sigui per IP
        if arp_registries == False:
            arp_registries= get_registry_by("ip",paq[ARP].psrc)
            
        
        #si el registre existeix, comprovem que no sigui spoofejat o hi hagui hagut algun canvi
        if arp_registries != False:
            
            arp_spoof = True
            
            for arp_registry in arp_registries:
            
                #si ja existeix amb la mateixa IP i MAC no sera spoof i el lactualitzarem com a vist recentment
                if arp_registry["ip"] == paq[ARP].psrc and  arp_registry["mac"] == paq[ARP].hwsrc:
                    arp_spoof = False
                    
                    #actualitzem lultim cop que sha vist el host si fa mes de un minut de lultima vegada
                    ara = datetime.now()
                    abans = datetime.strptime(arp_registry["last_seen"],"%Y-%m-%d %H:%M:%S")
                    
                    if (ara-abans).seconds > 60: 
                        change_registry_by_id(arp_registry["id"],["last_seen",ara.strftime("%Y-%m-%d %H:%M:%S")])


            if arp_spoof == True:
                log_text= "ARP spoofing/IP change detected. New registry has been created: IP "+str(paq[ARP].psrc)+" ; MAC "+str(paq[ARP].hwsrc)
                add_to_log(log_text)
                add_to_cua_alert("spoof",log_text)

                #netejem la variable per guardar-lo com si fos un nou valor
                arp_registries = False
                spoof = "Y"
            


        # afegim un nou host
        if arp_registries == False:

            #id per el registre
            arp_id = 1
            if len(taula_arp) != 0:
                arp_id = int(taula_arp[-1]["id"]) + 1
                
            ara= datetime.now()

            paquet = {
                "id":str(arp_id),
                "hostname":"",
                "ip":paq[ARP].psrc,
                "mac":paq[ARP].hwsrc,
                "first_seen":ara.strftime("%Y-%m-%d %H:%M:%S"),
                "last_seen":ara.strftime("%Y-%m-%d %H:%M:%S"),
                "spoof":spoof,
                "hidden":"N"}

            taula_arp.append(paquet)
            log_text= "New registry: ID "+str(arp_id)+" ; IP "+str(paq[ARP].psrc)+" ; MAC "+str(paq[ARP].hwsrc)
            add_to_log(log_text)
            
            #posem el correu en cua si es dona el cas que no hem apuntat cap spoof
            if spoof == "N":
                add_to_cua_alert("new_host",log_text)
                
            table_arp_has_changed()
        
        proccesing_packet_on = False
       
 


def arp_discovery(verbose='N'):
    if verbose == 'Y':
        print("[*] ARP Discovery sent to the target network.")
        
    arp_discovery = Ether(dst="ff:ff:ff:ff:ff:ff", src=config_loaded["MAC_SRC"]) / ARP(pdst=config_loaded["NET_SNIFF"], psrc=config_loaded["IP_SRC"])
    sendp(arp_discovery, verbose=0)
    
    
def send_queued_alerts():
    global config_loaded, taula_alert, cua_alert
    
    #enviem alertes, si tenim alertes creades, la configuracio SMTP esta OK i tenim alertes en cua
    if len(taula_alert) > 0 and check_smtp_config('N')== True and len(cua_alert)>0:
        
        #guardem quins arrays shauran de netejar. Si hem enviat correus, el netejem
        flush_type=[]
        
        for alert in taula_alert:
            
            for alert_type, alert_msg in cua_alert.items():
                if alert_type == alert['when']:
                    #enviem lalerta
                    send_alert(alert['to'],alert_msg)
                    
                    #afegim a larray el tipus de alerta per esborrarla un cop estiguem de enviar el missatge
                    if alert_type not in flush_type:
                        flush_type.append(alert_type)
                    
       
        #netejem la cua dalertes si pertoca
        if len(flush_type)>0:
            for alert_type in flush_type:
                del cua_alert[alert_type]
                
    
def hourly_thread():
    
    global config_loaded
    
    #auto discovery
    if config_loaded['ARP_DISC_ON'] == 'Y':
        #engegem lsniffer
        if sniffer_running == False:
            start_sniff()

        #fem un arp discovery
        arp_discovery()

    #enviem alertes, si tenim alertes creades, la configuracio SMTP esta OK i tenim alertes en cua
    send_queued_alerts()

 
    #recridem el proces cada hora
    hourly_thread_proc= threading.Timer(interval=3600,function=hourly_thread)
    hourly_thread_proc.daemon = True
    hourly_thread_proc.start()
    
    
#sniffer continuu que sempre executarem per tenir lsniffer en segon pla
def start_sniff(verbose='Y'):
    
    global sniffer_running, sniffer_proc
    
    if sniffer_running == False:
        sniffer_proc = AsyncSniffer(filter="arp", prn=process_packet) 
        sniffer_proc.start()
        sniffer_running = True
        msg= "The sniffer has been started. "
        
        if verbose == 'Y':
            
            print("[*] "+msg)
        
        add_to_log(msg)
            
    else:
        if verbose == 'Y':
            print("[!] The sniffer was already running. ")
            


#parem lsniffer
def stop_sniff(verbose='Y'):
    
    global sniffer_running, sniffer_proc
    
    if sniffer_running == True:
        msg= "The sniffer has been stopped. "
        
        if verbose == 'Y':
            print("[*] "+msg)
        
        add_to_log(msg)
        sniffer_running = False
        
        #esperem a tencar lsniffer si esta processant informacio
        while proccesing_packet_on == True:
            time.sleep(1)
            
        sniffer_proc.stop()
        
        
def status_sniff():
    
    global sniffer_running
    
    if sniffer_running == True:
        print("[~] The sniffer is currently running. ")
    else:
        print("[~] The sniffer is currently closed. ")


# ------------------------------------------------------------------------------------------
# SNIFF ------------------------------------------------------------------------------------
# ------------------------------------------------------------------------------------------


# ------------------------------------------------------------------------------------------
# SMTP -------------------------------------------------------------------------------------
# ------------------------------------------------------------------------------------------

#importem/creem el fitxer de config SMTP si pertoca
def load_smtp_config(force_creation='N'):
    
    global smtp_config

    #carreguem el fitxer de configuracio
    if os.path.exists(smtp_config_file):
        with open(smtp_config_file, 'r',encoding="utf-8") as f:
            smtp_config = json.load(f)
    
    #si no existeix, generem el fitxer de configuracio
    elif os.path.exists(smtp_config_file) == False  and force_creation=='S':
         #port = 465  # For SSL
      
    
        while check_smtp_config() == False:
            print("\r")
            print("[~] Let's configure the email we will use for sending email alerts: ")
            port = check_input_regex("Enter the SMTP port number: ","number")
            smtp_server = check_input_regex("Enter the SMTP server name: ","smtp_server")
            sender_email = check_input_regex("Enter the email address: ","email")
            sender_password = input("Enter the password: ")
            #crypt_password= input(" Enter a password for encrypting your saved credentials. This will be asked every time you open ARP Guard: ")
            ssl_enabled = check_input("Is SSL/TLS enabled? [y/n]: ",["y","n"])
            
            smtp_config = {"PORT":port, "SERVER":smtp_server, "EMAIL":sender_email, "PASSWORD":sender_password,"SSL_ENABLED":ssl_enabled}
            print("\r")

        with open(smtp_config_file, 'w',encoding="utf-8") as f:
            f.write(json.dumps(smtp_config))
            print("\r[*] The SMTP config file has been created. \r")




#retorna un handler de la connexio amb el servidor SMTP
def connect_smtp():
    global smtp_config
    
    #creem la connexio amb el servidor
    try:
        if smtp_config['SSL_ENABLED'] == 'y':
            context = ssl.create_default_context()
            server = smtplib.SMTP_SSL(smtp_config['SERVER'], smtp_config['PORT'], context=context)

        else:
            server = smtplib.SMTP(smtp_config['SERVER'],smtp_config['PORT'])
    
    except Exception as e:
        print("[!] Couldn't not connect to the server. Verify the server name and port number. ")
        return False
    
    
    #ens intentem loguejar
    try:
        server.login(smtp_config['EMAIL'],smtp_config['PASSWORD'])
        return server
            
    except smtplib.SMTPAuthenticationError as e:
        error_code= e.smtp_code
        error_message = e.smtp_error.decode("utf-8")

        print("[!] An error has ocurred during email connection. Error code: "+str(error_code)+" - Error message: "+error_message)
        return False
    
    except smtplib.SMTPResponseException as e:
        error_code= e.smtp_code
        error_message = e.smtp_error.decode("utf-8")

        #Gmail error
        if error_code == 535 and smtp_config['SERVER'] == "smtp.gmail.com":
            print("[!] An error has ocurred during email connection. You either entered a wrong username/password or you have access to less secure apps disabled. Please make sure that you have less secure apps enabled visiting:  https://www.google.com/settings/security/lesssecureapps ")

        else:
            print("[!] An error has ocurred during email connection. Error code: "+str(error_code)+" - Error message: "+error_message)

        return False
            
    except Exception as e:
        print("[!] Unknown exception. Please try again. ")
        return False
     


def check_smtp_config(verbose='S'):
    
    global smtp_config
    
    if smtp_config != {}:
    
        if verbose == 'S':
            print("[~]Checking SMTP config...")

        server = connect_smtp()
        #tenquem la connexio i retornem OK
        if server != False:
            server.quit()
            return True
    
    return False
    
    
     
def send_alert(to,message):
    
    global smtp_config

    header = "From:"+smtp_config['EMAIL']+"\r\nSubject:ARP Guard\r\n\r\n"
    message = header + message
    
    server = connect_smtp()
    
    if server != False:
        try:
            server.sendmail(smtp_config['EMAIL'], to, message)
            server.quit()
            return True
            
        except Exception as e:
            server.quit()
            print("[!] Email alert couldn't be send.")
            
    return False
    
     
# ------------------------------------------------------------------------------------------
# SMTP -------------------------------------------------------------------------------------
# ------------------------------------------------------------------------------------------



# ------------------------------------------------------------------------------------------
# ALERT ------------------------------------------------------------------------------------
# ------------------------------------------------------------------------------------------

def show_table_alert():
    global taula_alert
    
    print("\r\r")
    
    #preparem els registres per la taula
    taula_alert_format = [["ID", "Send email to", "When"]]
    
    #agafem els registres a mostrar
    for reg in taula_alert:
        taula_alert_format.append([reg["id"], reg["to"], reg["when"]]) 
        
        
    #pintem la taula
    if len(taula_alert_format)>1:
        
        taula = texttable.Texttable()
        taula.set_cols_align(["l", "c", "c"]) # align de les columnes
        taula.add_rows(taula_alert_format)
        print(taula.draw())
        
    else:
        print("[?] There aren't any alerts set.")
        


def create_alert(to,when):
    global taula_alert
    
    when_trans= {"new_host":"host creation","spoof":"spoofing try / IP change"}
    
    for existing_alert in taula_alert:
        if existing_alert["to"] == to and existing_alert["when"] == when:
            print("[!] Duplicated alert: alert to "+to+" on "+when_trans[when]+" already exists.")
            return False
   
    #id per el registre
    alert_id = 1
    if len(taula_alert) != 0:
        alert_id = int(taula_alert[-1]["id"]) + 1

    alert = {
         "id":alert_id,
         "to": to,
         "when": when
    }
   
    taula_alert.append(alert)
    save_alerts()
    print("[*] "+to+" will be reported on "+when_trans[when]+".")
    return True


def delete_alert(alert_id):
    global taula_alert
    
    for i in range(len(taula_alert)):
        if str(taula_alert[i]["id"]) == alert_id:
            del taula_alert[i]
            print("[*] Alert with id = "+alert_id+" has been deleted. ")
            save_alerts()
            return True
        
    print("[?] Alert with id = "+alert_id+" not found. ")
    return False
    
         
          
         
# ------------------------------------------------------------------------------------------
# ALERT ------------------------------------------------------------------------------------
# ------------------------------------------------------------------------------------------


def clean_cmd():
    global config_loaded

    #netejem la pantalla
    if config_loaded != {}:
        if config_loaded["SO"] == "W":
            os.system("cls")
        elif config_loaded["SO"] == "L":
            os.system("clear")
            
            

        
        
def inicia():
     
    #generem les carpetes necesaries si no existeixen
    check_program_tree()

    #carreguem la configuracio del programa
    load_config()
    
    #carreguem la configuracio SMTP si existeix    
    load_smtp_config()
    
    #agafem les dades de la BBDD
    load_arp()

    #agafem les posibles alertes configurades
    load_alerts()
    
    #creem la configuracio SMTP si tenim alguna alerta i no tenim encara configurat el SMTP
    if check_smtp_config('N') == False and  len(taula_alert)>1:
        load_smtp_config('S')


    #parseja els arguments de consola
    get_arguments()

    #activem el thread de cada hora
    hourly_thread()
    
    #guardem el log que hem obert el programa
    add_to_log("ARP Guard has been opened by the user.")

    
    
    
    

def print_menu():
     
    print("\r\r")
    print("   ___                _____                     __")
    print("  / _ |  ____ ___    / ___/__ __ ___   ____ ___/ /")
    print(" / __ | / __// _ \  / (_ // // // _ \ / __// _  / ")
    print("/_/ |_|/_/  / ___/  \___/ \___/ \_._//_/   \___/  ")
    print("           /_/                                    ")
    print("                             Coded by @ajaxr3quest")
    print("--------------------------------------------------")
    print("\r")
    print("  (s)nif        - Start/stop sniffer              ")
    print("  (c)heck       - Check sniffer status            ")
    print("  (d)isc        - Send ARP Discovery              ")
    print("  (export)      - Export ARP table to a CSV file  ")
    print("  (import)      - Import ARP table from a CSV file")
    print("                                                  ")
    print("  (t)able       - Show all ARP registries         ")
    print("           (?)  - Unknown hosts                   ")
    print("           (*)  - Known hosts                     ")
    print("           (a)  - Active hosts                    ")
    print("           (s)  - Spoofing try or IP change       ")
    print("  (u)pdate      - Update an ARP registry          ")
    print("  (del)ete      - Delete an ARP registry          ")
    print("                                                  ")
    print("  (a)lert       - Show created email alerts       ")
    print("           (n)  - Create a new email alert        ")
    print("         (del)  - Delete an email alert           ")
    print("                                                  ")
    print("  (help) <opt>  - Help with a given option        ")
    print("  (e)xit        - Close the program               ")
    print("                                                  ")
    print("--------------------------------------------------")


def tenca():
    
    global config_loaded
    print("\r")
    
    #parem ARP_DISC_ON
    if config_loaded['ARP_DISC_ON'] == 'Y':
        config_loaded['ARP_DISC_ON'] = 'N'
        
    #guardem els canvis si ni havia algun
    save_arp()
    
    #parem lsniffer
    stop_sniff()
    
    #enviem alertes que haguin pogut quedar en cua
    send_queued_alerts()
    
    add_to_log("ARP Guard has been closed by the user.")
    print("Bye bye!")
    sys.exit()


if __name__ == "__main__":

    try:
        inicia()
        wrong_command = ["Did your cat fall asleep on your keyboard again?","Long Beeeeeeeeep Short beep Short beep.","Really George?","There ain't any AI in the world that could understand what you just typed.","Sorry but... I'm not going to do it.","It's coffee time."]


        while True:

            comanda = input("\narpguard> ").strip()

            if  comanda == "exit" or comanda == "e": # tencar el programa
                tenca()


            elif comanda == "sniff" or comanda == "s": # activem/desactivem lsniffer infinit
                if sniffer_running == False:
                    start_sniff()
                else:
                    stop_sniff()


            elif comanda == "check" or comanda == "c": # mirem lstat del sniffer
                status_sniff()


            elif comanda == "disc" or comanda == "d": # fem un ARP Discovery

                reopen_sniff= False
                #iniciem lsniffer si estava parat
                if sniffer_running == False:
                    start_sniff('N')
                    reopen_sniff=True

                arp_discovery('Y')

                #tornem a tencar lsniffer si lhem iniciat amb lARP discovery
                if reopen_sniff == True:
                    time.sleep(1)
                    stop_sniff('N')


            # mostra la taula ARP    
            elif len(comanda)>0 and comanda[0] == "t": 

                table_action, table_params = get_table_params(comanda.strip())

                #sintaxis incorrecte
                if table_action == False and table_params == False:
                    print("[!] Syntax error. Syntax: table/t[option] -where <param> = X ")

                #mostra la taula segons filtre
                else:
                    show_table_arp(table_action,table_params)



            # edicio de la taula ARP    
            #format: update/u -set <param> = X -where <param> = X
            elif re.search(r'^(u |update ).*$', comanda) != None: 

                set_param, where_param = get_update_arp_params(comanda)

                #actualitzem
                if type(set_param) == list or type(where_param) == list:

                    arp_registry= get_registry_by(where_param[0],where_param[1])
                    if arp_registry != False:

                        #tenim multiples resultats
                        if len(arp_registry) > 1 :
                            print("[~] More than one registry has been found. Choose one by ID: ")
                            for registry in arp_registry:
                                print("    ID "+str(registry["id"])+" ; HOSTNAME "+str(registry["hostname"])+" ; IP "+str(registry["ip"])+" ; MAC "+str(registry["mac"]) )

                        else:
                            change_registry_by_id(arp_registry[0]["id"],set_param)

                    else:
                        print("[!] Please, don't drink and update at the same time, you will thank me later. ")


            #eliminem un registre de la taula ARP
            #format: delete/del -where <param> = X
            elif re.search(r'^(del |delete ).*$', comanda) != None:

                where_param = get_delete_arp_params(comanda)

                #eliminem
                if type(where_param) == list:

                    arp_registry= get_registry_by(where_param[0],where_param[1])
                    if arp_registry != False:

                        #tenim multiples resultats
                        if len(arp_registry) > 1 :
                            print("[~] More than one registry has been found. Choose one by ID: ")
                            for registry in arp_registry:
                                print("    ID "+str(registry["id"])+" ; HOSTNAME "+str(registry["hostname"])+" ; IP "+str(registry["ip"])+" ; MAC "+str(registry["mac"]) )

                        else:
                            change_registry_by_id(arp_registry[0]["id"],["hidden","Y"])

                    else:
                        print("[!] Do you think it is possible to delete something that does not exist at all?")



            #mostrem les alertes creades
            elif  comanda in ["alert","a"]:
                show_table_alert()




            #creem una nova alerta
            #an -to foo@mail.com foo2@mail.com ... -when <option>
            elif re.search(r'^(an |alertn ).*$', comanda) != None:

                #mirem que la info per enviar correus existeixi
                if check_smtp_config('N') == False:
                    load_smtp_config('S')

                to_param, when_param = get_create_alert_params(comanda)

                #creem la alerta
                if type(to_param) == list and when_param != False:
                    for email in to_param:
                        create_alert(email,when_param)



            #eliminem una alerta
            #adel -when <option>
            elif re.search(r'^(adel |alertdel ).*$', comanda) != None:
                alert_id= get_delete_alert_id(comanda)
                if alert_id != False:
                    delete_alert(alert_id)


            #exportem el contingut de la taula ARP a la carpeta export en format csv
            elif re.search(r'^(export ).*$', comanda) != None:
                comanda_opcio = comanda.split()

                if len(comanda_opcio) == 2:
                    export_arp_table(comanda_opcio[1].strip())
                else:
                    print("[!] Syntax error. Syntax: export <filename> ")




            #importem el contingut de un csv a la taula ARP
            elif re.search(r'^(import ).*$', comanda) != None:
                comanda_opcio = comanda.split()

                if len(comanda_opcio) == 2:
                    import_arp_table(comanda_opcio[1].strip())
                else:
                    print("[!] Syntax error. Syntax: import <filename> ")



            #print help
            elif re.search(r'^(help ).*$', comanda) != None:
                comanda_opcio = comanda.split()[1].strip()

                if comanda_opcio in ["s","sniff"]:
                    print("[~] (s)nif: called by 's' or 'sniff'. It starts or stops the sniffer based on its current status. ")

                elif comanda_opcio in ["c","check"]:
                    print("[~] (c)heck: called by 'c' or 'check'. It checks the current sniffer status. Just in case your cat has started it and you didn't realised. ")

                elif comanda_opcio in ["d","disc"]:
                    print("[~] (d)isc: called by 'd' or 'disc'. It sends ARP requests to every host on the target network, gatherhing all current hosts alive. It is basically an ARP sweep. Don't use it if you want to be stealthy. ")

                elif comanda_opcio  in ["t","table"]:
                    print("[~] (t)able: called by 't' or 'table'. Show hosts which had sent at least one ARP request or ARP reply on the target network. ")
                    print("\n[~] Filters: ")
                    print("    table?/t? -> Unknown hosts: show registries with empty hostname. ")
                    print("    table*/t* -> Known hosts: show registries with hostname set. ")
                    print("    tablea/ta -> Active hosts: show hosts that have sent some ARP reply/request in the last 3 minutes.  ")
                    print("    tables/ts -> Spoofing try or an IP has been changed: another registry already has the same IP or MAC address.")
                    print("                 Show the registries which have spoof = Y ")
                    print("\n[~] Extra filters: ")
                    print("    -where <field> = X : show registries which have the specified value. It works as an SQL like statement. Valid fields: hostname, id, ip, mac or spoof")

                elif comanda_opcio  in ["u","update"]:
                    print("[~] (u)pdate: called by 'u' or 'update'. It updates one registry from the ARP table. ")
                    print("\n[~] Syntax: ")
                    print("    -set   <field> = X : field and value that we would like to update. Valid fields: hostname, id, ip, mac or spoof ")
                    print("    -where <field> = X : field and value which indentifies one registry. Valid fields: hostname, id, ip or mac. ")
                    print("                         If we found more than one result, we must identify the registry by ID. ")

                elif comanda_opcio  in ["del","delete"]:
                    print("[~] (del)ete: called by 'del' or 'delete'. It deletes one registry from the ARP table. In fact, it updates it with hidden = Y. ")
                    print("\n[~] Syntax: ")
                    print("    -where <field> = X : field and value which indentifies one registry. Valid fields: hostname, id, ip or mac. ")
                    print("                         If we found more than one result, we must identify the registry by ID. ")

                elif comanda_opcio == "import":
                    print("[~] (import): called by 'import'. It parses the content of one CSV file and imports it as the current ARP table. File must be located at import directory. ")
                    print("     example: import my-backup  ")

                elif comanda_opcio == "export":
                    print("[~] (export): called by 'export'. It exports the content of the current ARP table to a CSV file. File must be located at export directory. ")
                    print("     example: export my-backup  ")


                elif comanda_opcio  in ["a","alert"]:
                    print("[~] (a)lert: called by 'a' or 'alert'. It show all created email alerts.")

                elif comanda_opcio  in ["an","alertn"]:
                    print("[~] (a)lert(n): called by 'an' or 'alertn'. It creates a new email alert when a given event is triggered. ")
                    print("\n[~] Syntax: ")
                    print("      -to <field> = X : email that will be notified. ")
                    print("    -when <field> = X : event that we want to catch. The possible events are 'new_host' and 'spoof'. ")
                    print("\n[~] Events: ")
                    print("     new_host: it will be triggered when a new host is added to the ARP table. ")
                    print("        spoof: it will be triggered when a spoofing try or an IP has been changed. ")


                elif comanda_opcio  in ["adel","alertdel"]:
                    print("[~] (a)lert(del): called by 'adel' or 'alertdel'. It deletes the target alert.")
                    print("\n[~] Syntax: ")
                    print("    -where id = X : ID which indentifies the alert we want to delete. ")


                elif comanda_opcio  in ["e","exit"]:
                    print("[~] If you need help with this command you shouldn't be using this software.")

                else:
                    print("[?] Wrong command. "+random.choice(wrong_command))

            elif comanda == '':
                pass

            else:

                print("[?] Wrong command. "+random.choice(wrong_command))

         

                    

    except KeyboardInterrupt:
        print("\r")
        tenca()
        
    #handle derrors
    except Exception as e:
        add_to_log(e)
