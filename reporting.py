class Reporting():

    def __init__(self, fileName):
        self.fileName = fileName

    def makeReport(self, identifiedAttacks, filesResult):

        #Try to open output file for writing
        try:
            with open(self.fileName, 'w') as writer:
                writer.write(
                        '----------------------------- RESULT ------------------------------')

                writer.write(
                    '\n\n----------------------- Idenitified Attacks -----------------------\n')
                if identifiedAttacks != []:
                    for attack in identifiedAttacks:
                        writer.write(str(attack) + '\n')
                else:
                    writer.write(str('No Attachks Detected'))
                writer.write(
                    '\n\n--------------------------- Files Results -------------------------\n')
                if filesResult != None:
                    for file in filesResult:
                        writer.write(str(file) + '\n')
                else:
                    writer.write(str('No File Found'))
                
                writer.close()
        except IOError:
            print('"{}" does not exist'.format(self.fileName))

