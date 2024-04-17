import json

class Debug:

    def __init__(self, logger=None):
        self.logger = logger
        self.debugTrace = {}

    def toJson(self):
        return json.dumps(self.debugTrace)

    def valueToStore(self, value, valueType):
        if valueType == 'byte.hex':
            if value is None:
                return 'None'
            else:
                return value.hex()
        elif valueType == 'byte.utf8':
            return value.decode('utf-8')
        elif valueType == 'int':
            if value is None:
                return 'None'
            else:
                return value
        else:
            raise Exception("valueType not implemented")

    def valueFromStore(self, valueFromStore, valueType):
        if valueType == 'byte.hex':
            if valueFromStore == 'None':
                return None
            else:
                return bytes.fromhex(valueFromStore)
        elif valueType == 'byte.utf8':
            return self.valueFromStore.encode('utf-8')
        elif valueType == 'int':
            if valueFromStore == 'None':
                return None
            else:
                return valueFromStore
        else:
            raise Exception("valueType not implemented")

    def setOrCheck(self, key, value, valueType='byte.hex'):
        valueToStore = self.valueToStore(value=value, valueType=valueType)
        if key not in self.debugTrace:
            self.debugTrace[key] = valueToStore
            return False
        else:
            assert(self.debugTrace[key] == valueToStore)
            return True

    def setOrGet(self, key, value, valueType='byte.hex', noneIfNew = False):
        if key not in self.debugTrace:
            self.debugTrace[key] = self.valueToStore(value=value, valueType=valueType)
            return None if noneIfNew else value
        else:
            return self.valueFromStore(valueFromStore=self.debugTrace[key], valueType=valueType)

    def get(self, key, valueType='byte.hex'):
        return self.valueFromStore(valueFromStore=self.debugTrace[key], valueType=valueType)
