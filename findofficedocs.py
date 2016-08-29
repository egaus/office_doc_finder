import multiprocessing
from time import sleep
import hashlib
import os
import requests
import urllib
from requests.auth import HTTPBasicAuth
import pandas as pd
import numpy as np
import math
from oletools.olevba import VBA_Parser
import sys
import yara

class Minion(multiprocessing.Process):
    def __init__(self, input, output, function, **args):
        multiprocessing.Process.__init__(self)
        self.input = input
        self.output = output
        self.function = function
        self.args = args
    
    def run(self):
        proc_name = self.name
        while True:
            next_task = self.input.get()
            if next_task is None:
                self.input.task_done()
                break
            result = self.function(next_task, self.args)
            self.input.task_done()
            self.output.put(result)


def parallelize(df, job_size, processes_per_cpu, function, **args):
    input = multiprocessing.JoinableQueue()
    output = multiprocessing.Queue()

    # Start minions
    num_minions = multiprocessing.cpu_count() * processes_per_cpu
    print "Because you have {} cpu's, you will get {} minions'".format(multiprocessing.cpu_count(), num_minions)
    minions = [ Minion(input, output, function, **args) for _ in xrange(num_minions) ]
    for minion in minions:
        minion.start()

    # Startup the jobs
    num_tasks = float(len(df))
    for i in xrange(int(math.ceil(num_tasks / job_size))):
        ceil = (i+1)*job_size
        if ceil > num_tasks:
            ceil = int(num_tasks)
        print "Tasking df.iloc[{}:{}]".format((i*job_size), ceil)
        input.put(df.iloc[(i*job_size) : ceil].copy())

    # Add a kill value for each minion
    for i in xrange(num_minions):
        input.put(None)

    # Wait for all minions to finish
    input.join()
    results = {}
    while num_minions:
        while output.qsize() > 0:
            result = output.get()
            results.update(result)
        num_minions -= 1
    print "All minions finished with {} results".format(len(results))
    return results


def download_macro_file(url, path):
    url = url.strip()
    local_filename = url.split('/')[-1]
    if local_filename == '':
        local_filename = 'no_name'
    try:
        r = requests.get(url, verify=False)
        md5sum = hashlib.md5(r.content).hexdigest()
        if not office_doc_checker(r.content):
            return {'md5sum':md5sum, 'filepath':None, 'filename':local_filename, 'url':url, 'dl_note':'not an office doc'}
        if not macro_checker(r.content):
            return {'md5sum':md5sum, 'filepath':None, 'filename':local_filename, 'url':url, 'dl_note':'no macros detected'}
        directory = os.path.join(path, md5sum)
        if not os.path.exists(directory):
            os.makedirs(directory)
            savedfile = os.path.join(directory, local_filename)
            with open(savedfile, "wb") as filehandle:
                filehandle.write(r.content)
                return {'md5sum':md5sum, 'filepath':savedfile, 'filename':local_filename, 'url':url, 'dl_note':'downloaded file with macros'}
        else:
            return {'md5sum':None, 'filepath':None, 'filename':local_filename, 'url':url, 'dl_note':'file already in library'}
    except Exception, e:
        print "Error: " + str(e)
        return {'md5sum':None, 'filepath':None, 'filename':local_filename, 'url':url, 'dl_note':'Error:'+str(e)}
    return {'md5sum':None, 'filepath':None, 'filename':local_filename, 'url':url, 'dl_note':'unknown issue'}


def download_macro_files(urls, path):
    '''
    :param url: 
    :param path:
    :return: either None in the case the file was not downloaded or a tuple with:
    (md5sum, filepath, filename)
    '''
    path = path['path']
    results = {}
    for i in range(len(urls)):
        url = urls.iloc[i]['url']
        results[urls.iloc[i].name] = download_macro_file(url, path)
    return results

def office_doc_checker(filedata):
    msoffice_file = '''
    rule office_document
    {
        meta:
            description = "Microsoft Office document"
        strings:
            $docfile = {d0 cf 11 e0}
            $docfile_xml = {50 4B 03 04}
        condition:
            $docfile at 0 or $docfile_xml at 0
    }
    '''
    rules = yara.compile(source=msoffice_file)
    matches = rules.match(data=filedata)
    return matches

def macro_checker(filedata):
    ''' 
    :param filedata: contents of file
    :return: True if file is macro-enabled, False otherwise 
    '''
    vbaparser = VBA_Parser('', data=filedata)
    if vbaparser.detect_vba_macros():
        return True
    else:
        return False


def bing_api(query, API_KEY, source_type = "Web", top = 1000, skip = 0, format = 'json'):
    # set search url
    query = '%27' + urllib.quote(query) + '%27'
    # web result only base url
    base_url = 'https://api.datamarket.azure.com/Bing/SearchWeb/' + source_type
    url = base_url + '?Query=' + query + '&$top=' + str(top) + '&$skip=' + str(skip) + '&$format=' + format
 
    user_agent = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_3) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/42.0.2311.135 Safari/537.36"
    headers = {'User-Agent': user_agent}
    auth = HTTPBasicAuth(API_KEY, API_KEY)
    response_data = requests.get(url, headers=headers, auth = auth)
    # decode json response content
    json_result = response_data.json()
    return json_result


if __name__ == "__main__":
    API_KEY = 'INSERT KEY'
    queries = ['.doc',
               '.dot',
               '.docm',
               '.docb',
               '.dotx',
               '.dotm',
               '.xls',
               '.xlsm',
               '.xlsb',
               '.xlt',
               '.xltm',
               '.xlam',
               '.xla',
               '.pptm',
               '.ppsm',
    ]
    for step in range(0,10000,50):
        for query in queries:
            resp = bing_api(query, API_KEY, source_type = "Web", top = 10000, skip = step, format = 'json')
            results = {}
            count = 0
            for result in resp['d']['results']:
                results[count] = {'url': result['Url'], 'id':result['ID']}
                count += 1
            print "URLs to process: {}".format(len(resp['d']['results']))
            df = pd.DataFrame(results).T
            df['url'] = df['url'].str.strip()
            results = parallelize(df, 15, 1, download_macro_files, path='./test')
            print "Processed: {}".format(len(results))
            import pdb; pdb.set_trace()
            newdf = pd.DataFrame(results).T
            filename = './test/bing_' + query + '_' + str(step) + '.csv'
            newdf.to_csv(filename)
