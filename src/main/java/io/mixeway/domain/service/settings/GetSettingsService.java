package io.mixeway.domain.service.settings;

import io.mixeway.db.entity.Settings;
import io.mixeway.db.repository.SettingsRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

/**
 * @author gsiewruk
 */
@Service
@RequiredArgsConstructor
public class GetSettingsService {
    private final SettingsRepository settingsRepository;

    public Settings getSettings(){
        return settingsRepository.findAll().stream().findFirst().orElse(null);
    }
}
