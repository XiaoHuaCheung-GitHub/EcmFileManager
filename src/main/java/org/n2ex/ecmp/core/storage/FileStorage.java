package org.n2ex.ecmp.core.storage;

import org.n2ex.ecmp.core.bean.EcmpFile;
import org.n2ex.ecmp.core.bean.EcmpPackage;
import org.n2ex.ecmp.core.bean.EcmpStorage;

import java.io.File;
import java.util.Map;
import java.util.Set;

public class FileStorage extends EcmpStorage implements IStorage{

    public FileStorage(String storagePath){
     this(storagePath,null);
    }


    /**
     *
     * @param storagePath directory: data starage path
     *                    file:     data storage  config file
     * @param key  if null ,data is not ecrypted
     */
    public FileStorage(String storagePath,String key){


    }


}
