package com.bsidessf.soothsayer;

import java.lang.reflect.Field;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;

class User {
    private static User user_instance = null;

    public String id;
    // Needs to be public to use built-in getter/setter

    public int score;
    public int seed;
    public List<Integer> guess;

    private User() {
        this.id = id;
        this.seed = 0;
        this.score = 0;
        this.guess = new ArrayList<Integer>();
    }
    public static Map<String, Object> parameters(Object obj) {
        Map<String, Object> map = new HashMap<>();
        for (Field field : obj.getClass().getDeclaredFields()) {
            field.setAccessible(true);
            try { map.put(field.getName(), field.get(obj)); } catch (Exception e) { }
        }
        return map;
    }
    public static synchronized User getInstance(){
        if (user_instance == null){
            user_instance = new User();
        }
        return user_instance;
    }
    public void reinitialize(String uid){
        this.id = uid;
        Random rand = new Random();
        this.seed = rand.nextInt(1000);
        this.score = 0;
        this.guess = new ArrayList<Integer>();
    }


}