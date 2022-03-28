package io.mixeway.domain.service.user;

import io.mixeway.db.entity.User;
import io.mixeway.db.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;

/**
 * @author gsiewruk
 */
@Service
@RequiredArgsConstructor
public class FindUserService {
    private final UserRepository userRepository;

    public List<User> findAll(){
        return userRepository.findAll();
    }
    public Optional<User> findById(Long id){
        return userRepository.findById(id);
    }
    public Optional<User> findByCommonName(String commonName){
        return userRepository.findByCommonName(commonName);
    }
    public Optional<User> findEnabledByUsername(String name) {
        return userRepository.findByUsernameAndEnabled(name, true);
    }
    public Optional<User> findByUsername(String username){
        return userRepository.findByUsername(username);
    }

    public Optional<User> findByUsernameOrCommonName(String name, String name1) {
        return userRepository.findByUsernameOrCommonName(name,name);
    }
}
