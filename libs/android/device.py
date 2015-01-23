class Device(object):
    """
    Android device definition.
    """

    def __init__(self, id=0, name=None, oem=None, tag=None):
        self._id = id
        self._name = name
        self._oem = oem
        self._tag = tag

    @property
    def id(self):
        return self._id

    @id.setter
    def id(self, value):
        self._id = int(value)

    @property
    def name(self):
        return self._name

    @name.setter
    def name(self, value):
        self._name = str(value)

    @property
    def oem(self):
        return self._oem

    @oem.setter
    def oem(self, value):
        self._oem = str(value)

    @property
    def tag(self):
        return self._tag

    @tag.setter
    def tag(self, value):
        self._tag = value

    def __str__(self):
        return "id %s\n\tName: %s\n\tOEM: %s\n" % (self.id, self.name, self.oem)