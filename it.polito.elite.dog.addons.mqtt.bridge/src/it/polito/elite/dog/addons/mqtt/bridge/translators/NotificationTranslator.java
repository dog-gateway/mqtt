/*
 * Dog - Addons - Mqtt
 * 
 * Copyright (c) 2013-2014 Dario Bonino
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License
 */
package it.polito.elite.dog.addons.mqtt.bridge.translators;

import org.osgi.service.log.Logger;

import it.polito.elite.dog.core.library.model.notification.Notification;

/**
 * The NotificationTranslator interface to be registered in the framework for
 * services offering translation between {@link Notification} instances and Mqtt
 * payloads.
 * 
 * @author <a href="mailto:dario.bonino@polito.it">Dario Bonino</a>
 *
 */
public interface NotificationTranslator
{
    public byte[] translateNotification(Notification notification);

    byte[] translateNotification(Notification notification, Logger logger);
}
