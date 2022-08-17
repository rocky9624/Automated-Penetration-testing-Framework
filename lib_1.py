import os
# file data extraction and processing
class dataProc:
    def __init__(self, fileName=None):
        self.proceed = False
        
        if fileName is not None:
            self.proceed = True
            self.filename = fileName
            self.contentList = []
            self.processContent()
            
    def reinitfile(self, fileName=""):
        self.proceed = False

        if len(fileName) is 0:
            print ("Please make sure you provide a file")
        else:
            self.proceed = True
            self.filename = fileName
            self.contentList = []

            self.processContent()

    def processContent(self):
        asciFile = self.filename
        file = open(asciFile)

        yourList = [line.rstrip('\n') for line in file]
        self.contentList = yourList

    def getContentList(self):
        return self.contentList

    def runCommand(self, command=""):
        if len(command) is 0:
            print("Ensure you have Pass a command")
        else:
            cmd = os.popen(command)
            cmd.close()

# file manegement will be at the heart of all the classes. as its components are shareable among other classes
# as an example ipExtract only extends with one function. in some cases you might need more than just one function depending on the task at hand
class ipExtract(dataProc):
    # extending the dataProc class with ipextraction components
        
    def processIp(self):
        dump = self.getContentList()
        #print (dump)
        iplist = []
        
        for each in dump:
            #print (each)
            if "inet " in each:
                tmp = each.split("inet ")[1].split(" ")[0]
                iplist.append(tmp)
                #print (tmp)
        return iplist

