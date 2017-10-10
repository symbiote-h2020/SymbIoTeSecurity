### Certificate acquisition
In order to acquire relevant certificates using directly the AAM endpoint the actor (user/platform owner) needs to provide his credentials and a Certificate Signing Request with the following specifics:
1.  
    Actor: common (either ordinary user (app) or platform owner) 

    AAM type: Core and Platform 
    
    Input format (CSR): CN=username@clientId@platformId (or SymbIoTe_Core_AAM for core user) 
    
    CSR's format in REGEX: ^(CN=)(([\w-])+)(@)(([\w-])+)(@)(([\w-])+)$ 
    
    Result: User client's certificate for acquiring HOME tokens 
    
2.
    Actor: Core AAM Admin 
    
    AAM type: Core 
        
    Input format (CSR): CN=componentId@SymbIoTe_Core_AAM 
        
    CSR's format in REGEX: ^(CN=)(([\w-])+)(@)(([\w-])+)$
        
    Result: Core components' certificate
    
3.
    Actor: Platform Owner
    
    AAM type: Core 
        
    Input format (CSR): CN=platformId
        
    CSR's format in REGEX: ^(CN=)(([\w-])+)$
        
    Result: Platform AAM's certificate
    
4.
    Actor: PO for R3, and for R3.1 Platform AAM Admin
        
    AAM type: Core 
           
    Input format (CSR): CN=componentId@platformId
            
    CSR's format in REGEX: ^(CN=)(([\w-])+)(@)(([\w-])+)$
            
    Result: Platform components' certificate
    
    