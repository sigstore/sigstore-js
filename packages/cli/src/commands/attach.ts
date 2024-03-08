/*
Copyright 2024 The Sigstore Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
import { Args, Command, Flags } from '@oclif/core';
import { bundleFromJSON } from '@sigstore/bundle';
import {
  Credentials,
  attachArtifactToImage,
  getImageDigest,
  getRegistryCredentials,
} from '@sigstore/oci';
import * as fs from 'fs/promises';
import { ImageRef, parseImageName } from '../oci/name';

export default class Attach extends Command {
  static override description = 'attach an attestation to a container image';
  static override examples = [
    '<%= config.bin %> <%= command.id %> --attestation <file> <name>{:<tag>|@<digest>}',
  ];

  static override flags = {
    attestation: Flags.file({
      description: 'attestation bundle to attach',
      required: true,
      allowStdin: true,
    }),
    username: Flags.string({
      description: 'username for the registry',
      required: false,
      char: 'u',
      dependsOn: ['password'],
    }),
    password: Flags.string({
      description: 'password for the registry',
      required: false,
      char: 'p',
      dependsOn: ['username'],
    }),
  };

  static override args = {
    'image-uri': Args.string({
      description: 'fully qualified URI to the image',
      required: true,
    }),
  };

  public async run(): Promise<void> {
    const { args, flags } = await this.parse(Attach);

    // Grab the attestation
    const artifact = await fs.readFile(flags['attestation']);
    const bundle = bundleFromJSON(JSON.parse(artifact.toString()));

    // Parse the image reference
    const imageRef = parseImageName(args['image-uri']);

    // Collect credentials either from flags or from the Docker config
    const credentials =
      flags['username'] && flags['password']
        ? { username: flags['username'], password: flags['password'] }
        : this.getRegistryCredentials(imageRef.name);

    const imageDigest = await this.getImageDigest(imageRef, credentials);

    const descriptor = await attachArtifactToImage({
      imageName: imageRef.name,
      imageDigest,
      credentials,
      artifact,
      mediaType: bundle.mediaType,
    });

    this.logToStderr('Artifact attached to image:', descriptor.digest);
  }

  private getRegistryCredentials(imageName: string): Credentials {
    try {
      const credentials = getRegistryCredentials(imageName);

      if (!credentials.username || !credentials.password) {
        throw new Error('No credentials found for registry');
      }
      return credentials;
    } catch (err) {
      throw new Error(
        'Error getting registry credentials. Make sure you are authenticated.'
      );
    }
  }

  private async getImageDigest(
    imageRef: ImageRef,
    credentials: Credentials
  ): Promise<string> {
    if (imageRef.digest) {
      return imageRef.digest;
    } else if (imageRef.tag) {
      return getImageDigest({
        credentials,
        imageName: imageRef.name,
        imageTag: imageRef.tag,
      });
    } else {
      throw new Error('No digest found for image');
    }
  }
}
