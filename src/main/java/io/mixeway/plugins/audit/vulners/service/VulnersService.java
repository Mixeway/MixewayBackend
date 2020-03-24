package io.mixeway.plugins.audit.vulners.service;

import io.mixeway.db.entity.Asset;
import io.mixeway.db.entity.Interface;
import io.mixeway.db.entity.SoftwarePacket;
import io.mixeway.db.repository.AssetRepository;
import io.mixeway.db.repository.InterfaceRepository;
import io.mixeway.db.repository.SoftwarePacketRepository;
import io.mixeway.plugins.audit.vulners.model.Packets;
import io.mixeway.pojo.LogUtil;
import io.mixeway.pojo.Status;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;

import java.util.*;

@Service
public class VulnersService {
    private final AssetRepository assetRepository;
    private final SoftwarePacketRepository softwarePacketRepository;
    private final InterfaceRepository interfaceRepository;

    public VulnersService(AssetRepository assetRepository, SoftwarePacketRepository softwarePacketRepository, InterfaceRepository interfaceRepository){
        this.interfaceRepository = interfaceRepository;
        this.assetRepository = assetRepository;
        this.softwarePacketRepository = softwarePacketRepository;
    }
    private static final Logger log = LoggerFactory.getLogger(VulnersService.class);

    public ResponseEntity<Status> savePacketDiscovery(Packets packets){
        log.info("Packet discovery for: {}, {} packets found", LogUtil.prepare(packets.getHostname()), packets.getPackets().size());

        Optional<Asset> asset = assetRepository.findByName(packets.getHostname());
        if(asset.isPresent()) {
            asset.get().setOs(packets.getOs());
            asset.get().setOsversion(packets.getVersion());
            assetRepository.save(asset.get());
            for (String ip: packets.getIps()) {
                Optional<Interface> intf = interfaceRepository.findByAssetAndPrivateip(asset.get(), ip);
                if (!intf.isPresent())
                    createInterfaceForAsset(asset.get(), ip);
            }
            loadPackets(asset.get(),packets.getPackets());
        } else
            createAssetFromPacket(packets);

        return new ResponseEntity<>(new Status("Ok"), HttpStatus.OK);
    }

    private void loadPackets(Asset asset, List<String> packets) {
        asset.getSoftwarePackets().removeAll(asset.getSoftwarePackets());
        for (String packet : packets) {
            Optional<SoftwarePacket> softPacket = softwarePacketRepository.findByName(packet);
            if (softPacket.isPresent())
                asset.getSoftwarePackets().add(softPacket.get());
            else {
                SoftwarePacket softPacketNew = new SoftwarePacket();
                softPacketNew.setName(packet);
                softwarePacketRepository.save(softPacketNew);
                asset.getSoftwarePackets().add(softPacketNew);
            }

        }
        assetRepository.save(asset);

    }
    private void createInterfaceForAsset(Asset asset, String ip) {
        Interface intf = new Interface();
        intf.setAsset(asset);
        intf.setActive(true);
        intf.setPrivateip(ip);
        interfaceRepository.save(intf);

    }
    private void createAssetFromPacket(Packets packets) {
        final Asset asset = new Asset();
        asset.setActive(true);
        asset.setName(packets.getHostname());
        asset.setOs(packets.getOs());
        asset.setOsversion(packets.getVersion());
        assetRepository.save(asset);
        for (String ip : packets.getIps()) {
            Interface intf = new Interface();
            intf.setPrivateip(ip);
            intf.setActive(true);
            intf.setAsset(asset);
            interfaceRepository.save(intf);
        }
        for (String packet : packets.getPackets()) {
            SoftwarePacket softPacket = new SoftwarePacket();
            softPacket.setName(packet);
            if(softPacket.getAssets() == null) {
                Set<Asset> assetSet = new HashSet<Asset>() {{
                    Optional<Asset> assetToSoft = assetRepository.findById(asset.getId());
                    assetToSoft.ifPresent(this::add);
                }};
                softPacket.setAssets(assetSet);
            }
            else
                softPacket.getAssets().add(asset);
            softwarePacketRepository.save(softPacket);
        }

    }
}
