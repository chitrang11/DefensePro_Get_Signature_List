from requests import Session
import config as cfg
import requests
import json
import csv
import os
import datetime
import glob


class Vision:

    def __init__(self, ip, username, password):
        self.ip = ip
        self.login_data = {"username": username, "password": password}
        self.base_url = "https://" + ip
        self.sess = Session()
        self.sess.headers.update({"Content-Type": "application/json"})
        self.login()

    def login(self):
        login_url = self.base_url + '/mgmt/system/user/login'
        try:
            r = self.sess.post(url=login_url, json=self.login_data, verify=False)
            r.raise_for_status()
            response = r.json()
        except (requests.exceptions.HTTPError, requests.exceptions.ConnectionError, requests.exceptions.SSLError,
                requests.exceptions.Timeout, requests.exceptions.ConnectTimeout,
                requests.exceptions.ReadTimeout) as err:
            raise SystemExit(err)

        if response['status'] == 'ok':
            self.sess.headers.update({"JSESSIONID": response['jsessionid']})
        # print("Auth Cookie is:  " + response['jsessionid'])
        else:
            exit(1)

    def FetchSignatureList(self):
        # Returns list of DP with mgmt IP, type, Name
        sig_list_url = self.base_url + '/mgmt/device/byip/' + cfg.DefensePro_MGMT_IP + '/config/rsIDSSignaturesProfileAttackListTable?filter=rsIDSSignaturesProfileAttackListProfileName:' + cfg.Signature_Profile_Name + '&filtertype=exact&filterRange=9000&props=rsIDSSignaturesProfileAttackListProfileName,rsIDSSignaturesProfileAttackListAttackID,rsIDSSignaturesProfileAttackListAttackName'
        r = self.sess.get(url=sig_list_url, verify=False)
        json_txt = r.json()
        # Print Signature List in Json
        # print(json_txt)
        jsonString = json.dumps(json_txt)
        jsonFile = open(JsonFile, "w+")
        jsonFile.write(jsonString)
        jsonFile.close()
        return json_txt

    def CovertJsonFileToCsv(self):
        # Opening JSON file and loading the data
        # into the variable data
        with open(JsonFile) as json_file:
            data = json.load(json_file)

        SigProAttackList_data = data['rsIDSSignaturesProfileAttackListTable']

        # open a CSV file for writing
        data_file = open(CsvFile, 'w+')

        # create the csv writer object
        csv_writer = csv.writer(data_file)

        # Counter variable used for writing
        # headers to the CSV file
        count = 0

        for SigProAttackList in SigProAttackList_data:
            if count == 0:
                # Writing headers of CSV file
                header = SigProAttackList.keys()
                csv_writer.writerow(header)
                count += 1

            # Writing data of CSV file
            csv_writer.writerow(SigProAttackList.values())
        data_file.close()

    def FetchDescForSig(self,attackID):
        sig_des_url = self.base_url + '/mgmt/system/realtimereporting/attackdescription?attackId=' + attackID
        r = self.sess.get(url=sig_des_url, verify=False)
        json_txt = r.json()
        # Print Signature Description
        # print(json_txt)
        return json_txt

    def UpdateSignatureFileWithDescription(self):
        with open(JsonFile) as json_file:
            data = json.load(json_file)
            for i in data["rsIDSSignaturesProfileAttackListTable"]:
                # print(i["rsIDSSignaturesProfileAttackListAttackID"])
                attackID= i["rsIDSSignaturesProfileAttackListAttackID"]
                SigDescription= self.FetchDescForSig(attackID)
                # Print Signature Description received from FetchDescForSig function
                #print (SigDescription)
                i.update(SigDescription)
        json_file.close()
        with open(JsonFile, 'w') as outfile:
            json.dump(data, outfile)
        v.CovertJsonFileToCsv()

    def CleanFile(self):
        with open(CsvFile) as filehandle:
            lines = filehandle.readlines()
        with open(CsvFile, 'w') as filehandle:
            lines = filter(lambda x: x.strip(), lines)
            filehandle.writelines(lines)
        
        # Get current time
        CurrentTime = datetime.datetime.now().timestamp()
        # print(CurrentTime)
        BackTime = CurrentTime - (cfg.FileRetention * 86400)      # 86400=24*60*60
        # print(BackTime)

        pattern = cfg.DefensePro_MGMT_IP + '_' + cfg.Signature_Profile_Name + '_*'
        files = glob.glob(pattern)

        for file in files:
            File_Last_Modified_time = os.path.getmtime(file)
            if File_Last_Modified_time < BackTime:
                os.remove(file)
                print(file + ' is old file and deleted')
        print(CsvFile + ' and ' + JsonFile + ' is created')


now = datetime.datetime.now()
Date_time = now.strftime("%Y-%m-%d_%H-%M-%S")
FileName = cfg.DefensePro_MGMT_IP + '_' + cfg.Signature_Profile_Name + '_' + Date_time
JsonFile = FileName+'.json'
CsvFile = FileName+'.csv'

v = Vision(cfg.VISION_IP, cfg.VISION_USER, cfg.VISION_PASS)
v.FetchSignatureList()
v.CovertJsonFileToCsv()
v.UpdateSignatureFileWithDescription()
v.CleanFile()
