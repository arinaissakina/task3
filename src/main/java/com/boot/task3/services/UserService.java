package com.boot.task3.services;

import com.boot.task3.entities.Users;
import com.boot.task3.repositories.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

@Service
public class UserService implements UserDetailsService {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private BCryptPasswordEncoder passwordEncoder;

    @Override
    public UserDetails loadUserByUsername(String s) throws UsernameNotFoundException {
        Users user = userRepository.findByEmail(s);
        if(user.isActive) {
            User securityUser = new User(user.getEmail(), user.getPassword(), user.getRoles());
            return securityUser;
        }
        return null;
    }

    public Users registerUser(Users user){
        user.setPassword(passwordEncoder.encode(user.getPassword()));
        return userRepository.save(user);
    }

    public Users updatePassword(Users user, String olpPass, String nPass){
        if(passwordEncoder.matches(olpPass, user.getPassword())){
            user.setPassword(passwordEncoder.encode(nPass));
            return userRepository.save(user);
        }
        return null;
    }
}
