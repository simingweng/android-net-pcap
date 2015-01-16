package com.jdsu.drivetest.anetpcap.sample;

import android.app.Activity;
import android.os.Bundle;
import android.util.Log;
import android.view.Menu;
import android.view.MenuItem;
import android.view.View;
import android.widget.Button;

import com.jdsu.drivetest.anetpcap.VolteESP;
import com.stericson.RootTools.RootTools;

import org.jnetpcap.JBufferHandler;
import org.jnetpcap.Pcap;
import org.jnetpcap.PcapHeader;
import org.jnetpcap.PcapIf;
import org.jnetpcap.nio.JBuffer;
import org.jnetpcap.packet.JPacket;
import org.jnetpcap.packet.JPacketHandler;
import org.jnetpcap.protocol.lan.SLL;

import java.io.File;
import java.util.ArrayList;
import java.util.List;


public class MainActivity extends Activity {

    private static final String TAG = MainActivity.class.getSimpleName();

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        Button openButton = (Button) findViewById(R.id.openButton);
        openButton.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                RootTools.installBinary(MainActivity.this, R.raw.singtel_volte_call, "singtel_volte_call.pcap");
                StringBuilder errs = new StringBuilder();
                final VolteESP esp = new VolteESP();
                Pcap pcap = Pcap.openOffline(new File(getFilesDir(), "singtel_volte_call.pcap").getAbsolutePath(), errs);
                pcap.loop(10, SLL.ID, new JPacketHandler<String>() {
                    @Override
                    public void nextPacket(JPacket packet, String user) {
                        Log.i(TAG, packet.toString());
                        if (packet.hasHeader(esp)) {
                            Log.i(TAG, "ESP decoded");
                        }
                    }
                }, "Simon");
                pcap.close();
            }
        });

        Button liveButton = (Button) findViewById(R.id.liveButton);
        liveButton.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                List<PcapIf> alldevs = new ArrayList<>(); // Will be filled with NICs
                StringBuilder errbuf = new StringBuilder(); // For any error msgs

                /***************************************************************************
                 * First get a list of devices on this system
                 **************************************************************************/
                int r = Pcap.findAllDevs(alldevs, errbuf);
                if (r == Pcap.NOT_OK || alldevs.isEmpty()) {
                    Log.e(TAG, String.format("Can't read list of devices, error is %s", errbuf.toString()));
                    return;
                }

                Log.i(TAG, "Network devices found:");

                int i = 0;
                for (PcapIf device : alldevs) {
                    String description =
                            (device.getDescription() != null) ? device.getDescription()
                                    : "No description available";
                    Log.i(TAG, String.format("#%d: %s [%s]\n", i++, device.getName(), description));
                }

                PcapIf device = alldevs.get(0); // We know we have atleast 1 device
                Log.i(TAG, String.format("\nChoosing '%s' on your behalf:\n",
                        (device.getDescription() != null) ? device.getDescription()
                                : device.getName()));

                /***************************************************************************
                 * Second we open up the selected device
                 **************************************************************************/
                int snaplen = 64 * 1024;           // Capture all packets, no trucation
                int flags = Pcap.MODE_PROMISCUOUS; // capture all packets
                int timeout = 10 * 1000;           // 10 seconds in millis
                Pcap pcap = Pcap.openLive(device.getName(), snaplen, flags, timeout, errbuf);

                if (pcap == null) {
                    Log.e(TAG, "Error while opening device for capture: "
                            + errbuf.toString());
                    return;
                }

                JBufferHandler<String> jBufferHandler = new JBufferHandler<String>() {
                    @Override
                    public void nextPacket(PcapHeader header, JBuffer buffer, String user) {
                        Log.i(TAG, String.format("received packet length %d", header.caplen()));
                    }
                };

                pcap.loop(10, jBufferHandler, "simon");
            }
        });
    }


    @Override
    public boolean onCreateOptionsMenu(Menu menu) {
        // Inflate the menu; this adds items to the action bar if it is present.
        getMenuInflater().inflate(R.menu.main, menu);
        return true;
    }

    @Override
    public boolean onOptionsItemSelected(MenuItem item) {
        // Handle action bar item clicks here. The action bar will
        // automatically handle clicks on the Home/Up button, so long
        // as you specify a parent activity in AndroidManifest.xml.
        int id = item.getItemId();
        if (id == R.id.action_settings) {
            return true;
        }
        return super.onOptionsItemSelected(item);
    }
}
