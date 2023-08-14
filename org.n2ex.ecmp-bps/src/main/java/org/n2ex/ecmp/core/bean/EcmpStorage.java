package org.n2ex.ecmp.core.bean;

import java.util.Map;
import java.util.Set;

public abstract class EcmpStorage {

    public EcmpPackage findById(String eId){
        return null;
    }
    public EcmpPackage findByIds(Set<String> eIds){
        return null;
    }
    public EcmpPackage find(Map<String,Object> condition){
        return null;
    }
    public String update(EcmpPackage ePkg){
        return null;
    }
    public String update(EcmpFile eFile){
        return null;
    }
    public EcmpPackage save(EcmpPackage eId){
        return null;
    }
    public int count(Map<String,Object> condition){
        return 0;
    }


    public void defragmentation(boolean asynchronous){

    }

}
