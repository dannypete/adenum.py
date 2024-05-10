from enum import Enum

class ADSchemaObjectClass(Enum):
    USER = 'user'
    GROUP = 'group'
    COMPUTER = 'computer'
    TRUSTED_DOMAIN = 'trustedDomain'
    FOREIGN_SECURITY_PRINCIPAL = 'foreignSecurityPrinciple'
    WILDCARD = '*'

    def __repr__(self) -> str:
        return self.value
    
    def __str__(self) -> str:
        return self.__repr__()

class ADSchemaObjectCategory(Enum):
    COMPUTER = "computer"
    GROUP = "group"
    USER = "user"
    WILDCARD = "*"
    PKI_ENROLLMENT_SERVICE = "pKIEnrollmentService"

    def __repr__(self) -> str:
        return self.value
    
    def __str__(self) -> str:
        return self.__repr__()