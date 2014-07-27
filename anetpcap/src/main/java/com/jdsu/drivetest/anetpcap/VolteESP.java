package com.jdsu.drivetest.anetpcap;

import org.jnetpcap.packet.JHeader;
import org.jnetpcap.packet.JPacket;
import org.jnetpcap.packet.JRegistry;
import org.jnetpcap.packet.RegistryHeaderErrors;
import org.jnetpcap.packet.annotate.Bind;
import org.jnetpcap.packet.annotate.Dynamic;
import org.jnetpcap.packet.annotate.Field;
import org.jnetpcap.packet.annotate.Header;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.tcpip.Tcp;

/**
 * Created by simingweng on 27/7/14.
 */
@Header(length = 8)
public class VolteESP extends JHeader {

    static {
        try {
            JRegistry.register(VolteESP.class);
            JRegistry.addBindings(VolteESP.class);
        } catch (RegistryHeaderErrors registryHeaderErrors) {
            registryHeaderErrors.printStackTrace();
        }
    }

    @Bind(to = Ip4.class)
    public static boolean bindToIp4(JPacket packet, Ip4 ip4) {
        return ip4.type() == 50;
    }

    @Bind(from = Tcp.class, to = VolteESP.class)
    public static boolean bindFromTcp(JPacket packet, VolteESP esp) {
        return esp.nextheader() == 6;
    }

    @Field(offset = 0, length = 32, format = "%d", description = "security parameter index")
    public long spi() {
        return getUInt(0);
    }

    @Field(offset = 32, length = 32, format = "%d", description = "sequence number")
    public long sqnum() {
        return getUInt(4);
    }

    @Field(format = "#mac#", description = "padding")
    public byte[] padding() {
        return getPacket().getByteArray(paddingOffset() / 8, padsize());
    }

    @Dynamic(Field.Property.OFFSET)
    public int paddingOffset() {
        return padsizeOffset() - padsize() * 8;
    }

    @Dynamic(Field.Property.LENGTH)
    public int paddingLength() {
        return padsize() * 8;
    }

    @Dynamic(field = "padding", value = Field.Property.CHECK)
    public boolean paddingCheck() {
        return padsize() > 0;
    }

    @Field(length = 8, format = "%d", description = "next header")
    public int nextheader() {
        return getPacket().getUByte(nextheaderOffset() / 8);
    }

    @Dynamic(Field.Property.OFFSET)
    public int nextheaderOffset() {
        return (getPacket().size() - 1 - 12) * 8;
    }

    @Field(length = 8, format = "%d", description = "padding size")
    public int padsize() {
        return getPacket().getUByte(padsizeOffset() / 8);
    }

    @Dynamic(Field.Property.OFFSET)
    public int padsizeOffset() {
        return nextheaderOffset() - 8;
    }

    @Override
    public int getPostfixLength() {
        return 12 + 2 + padsize();
    }
}
