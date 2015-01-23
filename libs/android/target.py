class Target(object):
    """

    """

    def __init__(self, id=0, altid=None, name=None, type=None, api_level=0, revision=None, skins=None):
        super(Target, self).__init__()
        self._id = id
        self._altid = altid
        self._name = name
        self._type = type
        self._api_level = int(api_level)
        self._revision = revision
        self._skins = skins

    @property
    def id(self):
        return self._id

    @id.setter
    def id(self, value):
        self._id = value

    @property
    def altid(self):
        return self._altid

    @altid.setter
    def altid(self, value):
        self._altid = value

    @property
    def name(self):
        return self._name

    @name.setter
    def name(self, value):
        self._name = value

    @property
    def type(self):
        return self._type

    @type.setter
    def type(self, value):
        self._type = value

    @property
    def api_level(self):
        return self._api_level

    @api_level.setter
    def api_level(self, value):
        self._api_level = int(value)

    @property
    def revision(self):
        return self._revision

    @revision.setter
    def revision(self, value):
        self._revision = value

    @property
    def skins(self):
        return self._skins

    @skins.setter
    def skins(self, value):
        self._skins = value

    def __str__(self):
        return "ID: %s\nAlternative ID: %s\nName: %s\nType: %s\nAPI level: %s\nRevision: %s\nSkins: %s" % (
            self._id, self._altid, self._name, self._type, self._api_level, self._revision, self._skins
        )
