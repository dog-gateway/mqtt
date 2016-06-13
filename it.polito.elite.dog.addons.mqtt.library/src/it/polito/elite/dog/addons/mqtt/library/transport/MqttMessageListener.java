/**
 * 
 */
package it.polito.elite.dog.addons.mqtt.library.transport;

import org.eclipse.paho.client.mqttv3.MqttMessage;

/**
 * @author bonino
 *
 */
public interface MqttMessageListener
{
	public void messageArrived(String topic, MqttMessage mqttMessage);
}
