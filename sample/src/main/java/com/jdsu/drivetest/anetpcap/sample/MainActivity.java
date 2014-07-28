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

import org.jnetpcap.Pcap;
import org.jnetpcap.packet.JPacket;
import org.jnetpcap.packet.JPacketHandler;
import org.jnetpcap.protocol.lan.SLL;

import java.io.File;


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
