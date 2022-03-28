package io.mixeway.domain.service.intf;

import io.mixeway.db.entity.Interface;
import io.mixeway.db.repository.InterfaceRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.Optional;

/**
 * @author gsiewruk
 */
@Service
@RequiredArgsConstructor
public class DeleteInterfaceService {
    private InterfaceRepository interfaceRepository;

    public void delete(Optional<Interface> interf){
        String assetName = interf.get().getAsset().getName();
        String projectName = interf.get().getAsset().getProject().getName();
        String ip = interf.get().getPrivateip();
        interf.ifPresent(interfaceRepository::delete);
    }
}
