package com.github.zollie.jsec.examples.config;

import java.util.Hashtable;
import java.util.Map.Entry;

/**
 * Holds Configuration for an App
 *
 * @author zollie
 */
public class AppConfig {
    private final Hashtable<String, Object> props = new Hashtable<String, Object>();

    /**
     * Default ctor
     */
    public AppConfig() {
    }

    /**
     * Mainly for testing
     *
     * @param props
     */
    public AppConfig(Hashtable<String, Object> props) {
    }

    /**
     * Get prop
     *
     * @param key
     * @return
     */
    public Object get(String key) {
        return props.get(key);
    }

    /**
     * Get as type
     *
     * @param key
     * @return
     */
    @SuppressWarnings("unchecked")
    public <T> T getAsType(String key) {
        return (T)props.get(key);
    }

    /**
     * Put prop
     *
     * @param key
     * @param value
     */
    public void put(String key, Object value) {
        props.put(key, value);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public String toString() {
        StringBuffer sb = new StringBuffer("AppConfig {\n");
        for(Entry<String, Object> e : props.entrySet())
            sb.append(e.getKey() + " = "+e.getValue()+"\n");
        sb.append("}");
        return sb.toString();
    }
}
