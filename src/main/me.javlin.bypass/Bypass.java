import com.github.ffalcinelli.jdivert.Packet;
import com.github.ffalcinelli.jdivert.WinDivert;
import com.github.ffalcinelli.jdivert.exceptions.WinDivertException;

import java.nio.ByteBuffer;

public class Bypass {
    public static void main(String[] args) {
        try {
            run();
        } catch (WinDivertException exception) {
            if(exception.getCode() == 5) {
                System.out.println("Failed to start packet interceptor! Run as administrator!");

                return;
            }

            exception.printStackTrace();
        }
    }

    public static void run() throws WinDivertException {
        System.out.println("Starting packet interceptor...");

        WinDivert intercept = new WinDivert("tcp.DstPort == 25565 and tcp.PayloadLength > 0");

        intercept.open();

        System.out.println("Waiting for MC connection...");

        boolean finished = false;
        boolean started = false;

        while(!finished) {
            Packet packet = intercept.recv();

            if(!started
                    && packet.getPayload()[getVarIntLength(packet.getPayload())] == 0
                    && packet.getPayload()[packet.getPayload().length - 1] == 2) {
                started = true;

                System.out.println("MC connection detected! Listening for plugin message packet...");
            }

            if(started && packet.getPayload().length == 32) {
                finished = true;

                ByteBuffer newData = ByteBuffer.wrap(packet.getPayload());

                newData.position(14);
                newData.put(newData.get());

                System.out.println("Packet replaced!");

                packet.setPayload(newData.array());
            }

            intercept.send(packet);
        }

        intercept.close();
    }

    public static int getVarIntLength(byte[] varint) {
        if(varint.length == 0)
            return 0;

        int count = 0;

        while(!isByteLast(varint[count]))
            count++;

        if(count > 5)
            return 0;

        return count + 1;
    }

    public static boolean isByteLast(int varint) {
        return (varint & 0b10000000) == 0;
    }
}
