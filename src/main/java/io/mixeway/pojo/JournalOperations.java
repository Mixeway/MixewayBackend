package io.mixeway.pojo;

import io.mixeway.db.entity.Project;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import io.mixeway.db.entity.Journal;
import io.mixeway.db.entity.User;
import io.mixeway.db.repository.JournalRepository;
import io.mixeway.db.repository.UserRepository;

import java.util.Optional;


@Component
public class JournalOperations {
    @Autowired
    JournalRepository journalRepository;
    @Autowired
    UserRepository userRepository;
    public void saveJournalEvent(String name, String cnname, Project project){
        Optional<User> user = userRepository.findByCommonName(cnname);
        Journal journal = new Journal();
        journal.setName(name);
        journal.setCnname(cnname);
        journal.setProject(project);
        journal.setUser(user.isPresent()? user.get():null);
        journalRepository.save(journal);

    }
}
